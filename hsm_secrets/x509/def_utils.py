from collections import defaultdict
from copy import deepcopy
from typing import Dict, List, Optional

from hsm_secrets.config import HSMConfig, KeyID, OpaqueObject, X509Cert, X509Info, find_config_items_of_class

"""
Utility functions for working with certificate definitions from the HSMConfig object.
"""


def merge_x509_info_with_defaults(x509_info: Optional[X509Info], hsm_config: HSMConfig) -> X509Info:
    """
    Merge an X509Info object with the default values from the HSMConfig object.

    This is used to fill in missing values in certificate definitions.
    """
    defaults = hsm_config.general.x509_defaults
    if x509_info is None:
        return deepcopy(defaults)

    merged = deepcopy(x509_info)

    merged.ca = defaults.ca if merged.ca is None else merged.ca

    if merged.path_len is None:
        merged.path_len = defaults.path_len

    if merged.validity_days is None:
        merged.validity_days = defaults.validity_days

    if merged.attribs is None:
        merged.attribs = deepcopy(defaults.attribs)
    else:
        for attr in ['organization', 'locality', 'state', 'country']:
            if getattr(merged.attribs, attr) is None:
                setattr(merged.attribs, attr, getattr(defaults.attribs, attr))

        if defaults.attribs:
            if not merged.attribs.subject_alt_names and defaults.attribs.subject_alt_names:
                merged.attribs.subject_alt_names = defaults.attribs.subject_alt_names.copy()

    if merged.key_usage is None:
        merged.key_usage = defaults.key_usage.copy() if defaults.key_usage else None

    if merged.extended_key_usage is None:
        merged.extended_key_usage = defaults.extended_key_usage.copy() if defaults.extended_key_usage else None

    if merged.name_constraints is None:
        merged.name_constraints = defaults.name_constraints.copy() if defaults.name_constraints else None

    return merged


def pretty_x509_info(x509_info: X509Info) -> str:
    """
    Pretty-print an X509Info object.
    """
    res =  f"path_len:           {x509_info.path_len}\n"
    res += f"validity_days:      {x509_info.validity_days}\n"
    res += f"key_usage:          {x509_info.key_usage}\n"
    res += f"extended_key_usage: {x509_info.extended_key_usage}\n"

    if x509_info.name_constraints:
        res += "name_constraints:\n"
        if name_dict := x509_info.name_constraints.permitted:
            res += "    permitted_subtrees:\n"
            for (k,v) in name_dict.items():
                res += f"        {k}: {v}\n"
        if name_dict := x509_info.name_constraints.excluded:
            res += "    excluded_subtrees:\n"
            for (k,v) in name_dict.items():
                res += f"        {k}: {v}\n"

    if x509_info.attribs:
        res += "attribs:\n"
        res += f"    common_name:       {x509_info.attribs.common_name}\n"
        res += f"    organization:      {x509_info.attribs.organization}\n"
        res += f"    locality:          {x509_info.attribs.locality}\n"
        res += f"    state:             {x509_info.attribs.state}\n"
        res += f"    country:           {x509_info.attribs.country}\n"
        if x509_info.attribs.subject_alt_names:
            res += f"    subject_alt_names: {x509_info.attribs.subject_alt_names}\n"
    else:
        res += "attribs: None\n"
    return res


def topological_sort_x509_cert_defs(cert_defs: List[OpaqueObject]) -> list[OpaqueObject]:
    """
    Sort a list of certificate definitions topologically based on their signing dependencies,
    such that the root CA certs come first, followed by intermediate certs, and finally leaf certs.
    Detects loops and raises an exception if found.
    """
    # Step 1: Build a dependency graph
    id_to_def = {cd.id: cd for cd in cert_defs}
    signer_to_signees: Dict[KeyID, List[KeyID]] = defaultdict(list)
    for cd in cert_defs:
        if cd.sign_by and cd.sign_by != cd.id:  # Skip self-signed certs
            signer_to_signees[cd.sign_by].append(cd.id)

    # Step 2: Perform a topological sort with loop detection
    sorted_certs: List[OpaqueObject] = []
    visited: set[KeyID] = set()
    in_path: set[KeyID] = set()

    def dfs(c: OpaqueObject):
        if c.id in in_path:
            raise Exception(f"Issuer/signing loop detected involving certificate id 0x{c.id:04x}")
        if c.id not in visited:
            visited.add(c.id)
            in_path.add(c.id)
            for signee_id in signer_to_signees.get(c.id, []):
                dfs(id_to_def[signee_id])
            sorted_certs.append(c)
            in_path.remove(c.id)

    for c in cert_defs:
        if c.id not in visited:
            dfs(c)

    assert len(sorted_certs) == len(cert_defs), "Topological sort failed to include all certificate definitions"
    sorted_certs.reverse()
    return sorted_certs


def find_cert_def(conf: HSMConfig, opaque_id: KeyID|int) -> Optional[X509Cert]:
    """
    Find a certificate definition by its opaque ID.
    """
    for cd in find_config_items_of_class(conf, X509Cert):
        assert isinstance(cd, X509Cert)
        for cs in cd.signed_certs:
            if cs.id == opaque_id:
                return cd
    return None
