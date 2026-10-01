"""
Cloud Security module.

Layout
------
    providers/     one connector per cloud provider (AWS, GCP), behind CloudProvider
    normalizers/   provider payload → normalized Vectra finding/asset
    registry.py    provider catalogue + capability model (incl. future providers)
    secrets.py     encryption of stored provider credentials
    access.py      server-side org resolution + cloud RBAC
    store.py       Firestore persistence (backend-only collections)
    sync.py        background synchronization engine

Everything outside providers/ and normalizers/ works on normalized objects only.
"""
