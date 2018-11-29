# The following are imported at the beginning to ensure that the
# patches are applied before any of the modules save a reference to
# the functions being patched. The order is also important.
from gbpservice.neutron.extensions import patch  # noqa

from gbpservice.neutron.plugins.ml2plus import patch_neutron  # noqa
