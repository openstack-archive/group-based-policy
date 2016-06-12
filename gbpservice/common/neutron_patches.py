from neutron.db import common_db_mixin

class CommonDbMixin(common_db_mixin.CommonDbMixin):
    def _get_tenant_id_for_create(self, context, res):
        return res['tenant_id']

