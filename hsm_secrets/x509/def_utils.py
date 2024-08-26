from collections import defaultdict
from copy import deepcopy
from typing import Dict, List, Optional

from hsm_secrets.config import HSMConfig, HSMKeyID, HSMOpaqueObject, X509Cert, X509Info, find_config_items_of_class

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

    if merged.validity_days is None:
        merged.validity_days = defaults.validity_days

    if merged.attribs is None:
        merged.attribs = deepcopy(defaults.attribs)
    else:
        # Assume common_name is set, and fill in missing values from defaults (if set)
        for attr in ['organization', 'locality', 'state', 'country']:
            if getattr(merged.attribs, attr) is None:
                setattr(merged.attribs, attr, getattr(defaults.attribs, attr))

    attributes_to_copy = [
        'basic_constraints',
        'key_usage',
        'extended_key_usage',
        'subject_alt_name',
        'issuer_alt_name',
        'name_constraints',
        'crl_distribution_points',
        'authority_info_access',
        'certificate_policies',
        'policy_constraints',
        'inhibit_any_policy'
    ]

    for attr in attributes_to_copy:
        merged_attr = getattr(merged, attr)
        defaults_attr = getattr(defaults, attr)
        if merged_attr:
            setattr(merged, attr, merged_attr)
        elif merged_attr is None and defaults_attr is not None:
            setattr(merged, attr, defaults_attr.model_copy(deep=True))
        else:
            setattr(merged, attr, None) # Remove if empty

    return merged


def pretty_x509_info(x509_info: X509Info) -> str:
    """
    Pretty-print an X509Info object.
    """
    res  = f"validity_days:      {x509_info.validity_days}\n"
    res += f"key_usage:          {x509_info.key_usage}\n"
    res += f"extended_key_usage: {x509_info.extended_key_usage}\n"

    if x509_info.basic_constraints:
        res += f"basic_constraints:  (critical: {x509_info.basic_constraints.critical})\n"
        res =  f"  path_len:         {x509_info.basic_constraints.path_len}\n"
        res += f"  ca:               {x509_info.basic_constraints.ca}\n"

    if x509_info.name_constraints:
        res += f"name_constraints:  (critical: {x509_info.name_constraints.critical})\n"
        if name_dict := x509_info.name_constraints.permitted:
            res += "    permitted_subtrees:\n"
            for (k,v) in name_dict.items():
                res += f"        {k}: {v}\n"
        if name_dict := x509_info.name_constraints.excluded:
            res += "    excluded_subtrees:\n"
            for (k,v) in name_dict.items():
                res += f"        - {k}: {v}\n"

    if x509_info.attribs:
        res += "attribs:\n"
        res += f"    common_name:       {x509_info.attribs.common_name}\n"
        res += f"    organization:      {x509_info.attribs.organization}\n"
        res += f"    locality:          {x509_info.attribs.locality}\n"
        res += f"    state:             {x509_info.attribs.state}\n"
        res += f"    country:           {x509_info.attribs.country}\n"
    else:
        res += "attribs: None\n"

    if x509_info.subject_alt_name:
        res += f"subject_alt_name:  (critical: {x509_info.subject_alt_name.critical})\n"
        for (k,v) in sorted(x509_info.subject_alt_name.names.items(), key=lambda x: x[0]):
            res += f"    - {k}: {v}\n"

    if x509_info.issuer_alt_name:
        res += f"issuer_alt_name:  (critical: {x509_info.issuer_alt_name.critical})\n"
        for (k,v) in sorted(x509_info.issuer_alt_name.names.items(), key=lambda x: x[0]):
            res += f"    - {k}: {v}\n"

    if x509_info.crl_distribution_points:
        res += f"crl_distribution_points:  (critical: {x509_info.crl_distribution_points.critical})\n"
        for url in x509_info.crl_distribution_points.urls:
            res += f"    - {url}\n"

    if x509_info.authority_info_access:
        res += f"authority_info_access:  (critical: {x509_info.authority_info_access.critical})\n"
        for url in x509_info.authority_info_access.ocsp:
            res += f"    - OCSP: {url}\n"
        for url in x509_info.authority_info_access.ca_issuers:
            res += f"    - CA Issuers: {url}\n"

    if x509_info.certificate_policies:
        res += f"certificate_policies:  (critical: {x509_info.certificate_policies.critical})\n"
        for policy in x509_info.certificate_policies.policies:
            res += f"    - {policy}\n"

    if x509_info.policy_constraints:
        res += f"policy_constraints:  (critical: {x509_info.policy_constraints.critical})\n"
        res += f"    require_explicit_policy: {x509_info.policy_constraints.require_explicit_policy}\n"
        res += f"    inhibit_policy_mapping: {x509_info.policy_constraints.inhibit_policy_mapping}\n"

    if x509_info.inhibit_any_policy:
        res += f"inhibit_any_policy:  (critical: {x509_info.inhibit_any_policy.critical})\n"
        res += f"    skip_certs: {x509_info.inhibit_any_policy.skip_certs}\n"

    return res


def topological_sort_x509_cert_defs(cert_defs: List[HSMOpaqueObject]) -> list[HSMOpaqueObject]:
    """
    Sort a list of certificate definitions topologically based on their signing dependencies,
    such that the root CA certs come first, followed by intermediate certs, and finally leaf certs.
    Detects loops and raises an exception if found.
    """
    # Step 1: Build a dependency graph
    id_to_def = {cd.id: cd for cd in cert_defs}
    signer_to_signees: Dict[HSMKeyID, List[HSMKeyID]] = defaultdict(list)
    for cd in cert_defs:
        if cd.sign_by and cd.sign_by != cd.id:  # Skip self-signed certs
            signer_to_signees[cd.sign_by].append(cd.id)

    # Step 2: Perform a topological sort with loop detection
    sorted_certs: List[HSMOpaqueObject] = []
    visited: set[HSMKeyID] = set()
    in_path: set[HSMKeyID] = set()

    def dfs(c: HSMOpaqueObject):
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


def find_cert_def(conf: HSMConfig, opaque_id: HSMKeyID|int) -> Optional[X509Cert]:
    """
    Find a certificate definition by its opaque ID.
    """
    for cd in find_config_items_of_class(conf, X509Cert):
        assert isinstance(cd, X509Cert)
        for cs in cd.signed_certs:
            if cs.id == opaque_id:
                return cd
    return None
