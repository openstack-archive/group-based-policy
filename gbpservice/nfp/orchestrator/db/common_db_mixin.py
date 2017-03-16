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

from neutron.db import sqlalchemyutils
import six
import weakref


# TODO(ashu): Below class need to extend neutron's CommonDbMixin.
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
        query_filter = None
        # Execute query hooks registered from mixins and plugins
        query_hooks = self._model_query_hooks.get(model, {})
        for _name, hooks in six.iteritems(query_hooks):
            query_hook = hooks.get('query')
            if isinstance(query_hook, six.string_types):
                query_hook = getattr(self, query_hook, None)
            if query_hook:
                query = query_hook(model, query)

            filter_hook = hooks.get('filter')
            if isinstance(filter_hook, six.string_types):
                filter_hook = getattr(self, filter_hook, None)
            if filter_hook:
                query_filter = filter_hook(model, query_filter)

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
            for key, value in six.iteritems(filters):
                column = getattr(model, key, None)
                if column:
                    query = query.filter(column.in_(value))

            query_hooks = self._model_query_hooks.get(model, {})
            for _name, hooks in six.iteritems(query_hooks):
                result_filter = hooks.get('result_filters', None)
                if isinstance(result_filter, six.string_types):
                    result_filter = getattr(self, result_filter, None)

                if result_filter:
                    query = result_filter(query, filters)
        return query

    def _apply_dict_extend_functions(self, resource_type,
                                     response, db_object):
        for func in self._dict_extend_functions.get(
                resource_type, []):
            args = (response, db_object)
            if isinstance(func, six.string_types):
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
        collection = sqlalchemyutils.paginate_query(
            collection, model, limit,
            sorts, marker_obj=marker_obj)
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
                    six.iteritems(data) if k in columns)
