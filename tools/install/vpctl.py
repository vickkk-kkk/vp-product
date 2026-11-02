#!/usr/bin/env python3
"""One local entry point; lifecycle and shared management API remain distinct."""
import sys
import vp_install
import vp_api
if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'fresh-local':
        import vp_fresh_cli
        sys.exit(vp_fresh_cli.main(sys.argv[2:]))
    actions = {'protocols', 'configure', 'apply-plan', 'snapshot', 'drafts', 'operation', 'export', 'build', *vp_api.vp_publications.ACTIONS}
    if len(sys.argv) > 1 and sys.argv[1] in actions:
        sys.exit(vp_api.main())
    sys.exit(vp_install.main())
