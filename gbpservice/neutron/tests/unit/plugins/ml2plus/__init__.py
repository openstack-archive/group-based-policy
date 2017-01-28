# The following are imported at the beginning to ensure
# that the patches are applied before any of the
# modules save a reference to the functions being patched
from gbpservice.neutron.plugins.ml2plus import patch_neutron  # noqa

from gbpservice.neutron.extensions import patch  # noqa
