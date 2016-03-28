# Copyright (c) 2014 OpenStack Foundation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import weakref

from six import moves
import sqlalchemy
from sqlalchemy.orm import properties


class BadRequest(Exception):
    pass


def paginate_query(query, model, limit, sorts, marker_obj=None):
    """Returns a query with sorting / pagination criteria added.

    Pagination works by requiring a unique sort key, specified by sorts.
    (If sort keys is not unique, then we risk looping through values.)
    We use the last row in the previous page as the 'marker' for pagination.
    So we must return values that follow the passed marker in the order.
    With a single-valued sort key, this would be easy: sort_key > X.
    With a compound-values sort key, (k1, k2, k3) we must do this to repeat
    the lexicographical ordering:
    (k1 > X1) or (k1 == X1 && k2 > X2) or (k1 == X1 && k2 == X2 && k3 > X3)
    The reason of didn't use OFFSET clause was it don't scale, please refer
    discussion at https://lists.launchpad.net/openstack/msg02547.html

    We also have to cope with different sort directions.

    Typically, the id of the last row is used as the client-facing pagination
    marker, then the actual marker object must be fetched from the db and
    passed in to us as marker.

    :param query: the query object to which we should add paging/sorting
    :param model: the ORM model class
    :param limit: maximum number of items to return
    :param sorts: array of attributes and direction by which results should
                 be sorted
    :param marker: the last item of the previous page; we returns the next
                    results after this value.
    :rtype: sqlalchemy.orm.query.Query
    :return: The query with sorting/pagination added.
    """
    if not sorts:
        return query

    # A primary key must be specified in sort keys
    assert not (limit and
                len(set(dict(sorts).keys()) &
                    set(model.__table__.primary_key.columns.keys())) == 0)

    # Add sorting
    for sort_key, sort_direction in sorts:
        sort_dir_func = sqlalchemy.asc if sort_direction else sqlalchemy.desc
        try:
            sort_key_attr = getattr(model, sort_key)
        except AttributeError:
            # Extension attribute doesn't support for sorting. Because it
            # existed in attr_info, it will be catched at here
            msg = _("%s is invalid attribute for sort_key") % sort_key
            raise BadRequest(resource=model.__tablename__, msg=msg)
        if isinstance(sort_key_attr.property, properties.RelationshipProperty):
            msg = _("The attribute '%(attr)s' is reference to other "
                    "resource, can't used by sort "
                    "'%(resource)s'") % {'attr': sort_key,
                                         'resource': model.__tablename__}
            raise BadRequest(resource=model.__tablename__, msg=msg)
        query = query.order_by(sort_dir_func(sort_key_attr))

    # Add pagination
    if marker_obj:
        marker_values = [getattr(marker_obj, sort[0]) for sort in sorts]

        # Build up an array of sort criteria as in the docstring
        criteria_list = []
        for i, sort in enumerate(sorts):
            crit_attrs = [(getattr(model, sorts[j][0]) == marker_values[j])
                          for j in moves.range(i)]
            model_attr = getattr(model, sort[0])
            if sort[1]:
                crit_attrs.append((model_attr > marker_values[i]))
            else:
                crit_attrs.append((model_attr < marker_values[i]))

            criteria = sqlalchemy.sql.and_(*crit_attrs)
            criteria_list.append(criteria)

        f = sqlalchemy.sql.or_(*criteria_list)
        query = query.filter(f)

    if limit:
        query = query.limit(limit)

    return query


class CommonDbMixin(object):
    """Common methods used in core and service plugins."""
    # Plugins, mixin classes implementing extension will register
    # hooks into the dict below for "augmenting" the "core way" of
    # building a query for retrieving objects from a model class.
    # To this aim, the register_model_query_hook and unregister_query_hook
    # from this class should be invoked
    _model_query_hooks = {}

    # This dictionary will store methods for extending attributes of
    # api resources. Mixins can use this dict for adding their own methods
    # TODO(salvatore-orlando): Avoid using class-level variables
    _dict_extend_functions = {}

    @classmethod
    def register_model_query_hook(cls, model, name, query_hook, filter_hook,
                                  result_filters=None):
        """Register a hook to be invoked when a query is executed.

        Add the hooks to the _model_query_hooks dict. Models are the keys
        of this dict, whereas the value is another dict mapping hook names to
        callables performing the hook.
        Each hook has a "query" component, used to build the query expression
        and a "filter" component, which is used to build the filter expression.

        Query hooks take as input the query being built and return a
        transformed query expression.

        Filter hooks take as input the filter expression being built and return
        a transformed filter expression
        """
        model_hooks = cls._model_query_hooks.get(model)
        if not model_hooks:
            # add key to dict
            model_hooks = {}
            cls._model_query_hooks[model] = model_hooks
        model_hooks[name] = {'query': query_hook, 'filter': filter_hook,
                             'result_filters': result_filters}

    @property
    def safe_reference(self):
        """Return a weakref to the instance.

        Minimize the potential for the instance persisting
        unnecessarily in memory by returning a weakref proxy that
        won't prevent deallocation.
        """
        return weakref.proxy(self)

    def _model_query(self, session, model, is_admin=False):
        query = session.query(model)
        # define basic filter condition for model query
        # NOTE(jkoelker) non-admin queries are scoped to their tenant_id
        # NOTE(salvatore-orlando): unless the model allows for shared objects
        query_filter = None
        # Execute query hooks registered from mixins and plugins
        for _name, hooks in self._model_query_hooks.get(model,
                                                        {}).iteritems():
            query_hook = hooks.get('query')
            if isinstance(query_hook, basestring):
                query_hook = getattr(self, query_hook, None)
            if query_hook:
                query = query_hook(model, query)

            filter_hook = hooks.get('filter')
            if isinstance(filter_hook, basestring):
                filter_hook = getattr(self, filter_hook, None)
            if filter_hook:
                query_filter = filter_hook(model, query_filter)

        # NOTE(salvatore-orlando): 'if query_filter' will try to evaluate the
        # condition, raising an exception
        if query_filter is not None:
            query = query.filter(query_filter)
        return query

    def _fields(self, resource, fields):
        if fields:
            return dict(((key, item) for key, item in resource.items()
                         if key in fields))
        return resource

    def _get_tenant_id_for_create(self, resource):
        return resource['tenant_id']

    def _get_by_id(self, session, model, id):
        query = self._model_query(session, model)
        return query.filter(model.id == id).one()

    def _apply_filters_to_query(self, query, model, filters):
        if filters:
            for key, value in filters.iteritems():
                column = getattr(model, key, None)
                if column:
                    query = query.filter(column.in_(value))
            for _name, hooks in self._model_query_hooks.get(model,
                                                            {}).iteritems():
                result_filter = hooks.get('result_filters', None)
                if isinstance(result_filter, basestring):
                    result_filter = getattr(self, result_filter, None)

                if result_filter:
                    query = result_filter(query, filters)
        return query

    def _apply_dict_extend_functions(self, resource_type,
                                     response, db_object):
        for func in self._dict_extend_functions.get(
            resource_type, []):
            args = (response, db_object)
            if isinstance(func, basestring):
                func = getattr(self, func, None)
            else:
                # must call unbound method - use self as 1st argument
                args = (self,) + args
            if func:
                func(*args)

    def _get_collection_query(self, session, model, filters=None,
                              sorts=None, limit=None, marker_obj=None,
                              page_reverse=False):
        collection = self._model_query(session, model)
        collection = self._apply_filters_to_query(collection, model, filters)
        if limit and page_reverse and sorts:
            sorts = [(s[0], not s[1]) for s in sorts]
        collection = paginate_query(collection, model, limit, sorts,
                                    marker_obj=marker_obj)
        return collection

    def _get_collection(self, session, model, dict_func, filters=None,
                        fields=None, sorts=None, limit=None, marker_obj=None,
                        page_reverse=False):
        query = self._get_collection_query(session, model, filters=filters,
                                           sorts=sorts,
                                           limit=limit,
                                           marker_obj=marker_obj,
                                           page_reverse=page_reverse)
        items = [dict_func(c, fields) for c in query]
        if limit and page_reverse:
            items.reverse()
        return items

    def _get_collection_count(self, model, filters=None):
        return self._get_collection_query(model, filters).count()

    def _get_marker_obj(self, resource, limit, marker):
        if limit and marker:
            return getattr(self, '_get_%s' % resource)(marker)
        return None

    def _filter_non_model_columns(self, data, model):
        """Filter non model columns

        Remove all the attributes from data which are not columns of
        the model passed as second parameter.
        """
        columns = [c.name for c in model.__table__.columns]
        return dict((k, v) for (k, v) in
                    data.iteritems() if k in columns)
