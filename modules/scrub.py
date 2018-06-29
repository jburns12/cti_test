import re
from modules import download, lookup

def append_custom_fields(json_blob):
    """Append x_mitre custom fields to Description."""
    try:
        for obj in json_blob:
            if (obj['attributes']['description']):
                attributes = ['x_mitre_detection', 'x_mitre_platforms',
                 'x_mitre_data_sources', 'x_mitre_effective_permissions',
                'x_mitre_defense_bypassed', 'x_mitre_permissions_required',
                'x_mitre_system_requirements', 'x_mitre_remote_support',
                'x_mitre_network_requirements', 'x_mitre_contributors',
                'x_mitre_aliases', 'x_mitre_collections']

                for attribute in attributes:
                    try:
                        if (obj['attributes'][attribute]):
                            if (attribute == 'x_mitre_collections'):
                                del obj['attributes'][attribute]
                    except KeyError as ex:
                        pass 

    except KeyError as ex:
        pass

    return json_blob

def filter_identity(json_blob):
    for obj in json_blob:
        obj = obj['attributes']
        if obj['sectors']:
            del obj['sectors']
        if obj['x_mitre_collections']:
            del obj['x_mitre_collections']

    return json_blob

def filter_by_id(json_blob, lookup):
    """Copy objects with valid source_name properties into a new JSON blob."""
    valid_sources = ['mitre-attack', 'mitre-pre-attack', 'mitre-mobile-attack']
    output = []
    for obj in json_blob:
        if obj['type'] != 'relationship':
            try:
                for ext_ref in obj['attributes']['external_references']:
                    if ext_ref['source_name'] in valid_sources and ext_ref['external_id']:
                        output.append(obj)
            except KeyError as ex:
                pass 
        else:
            if (obj['attributes']['source_ref'] in lookup and obj['attributes']['target_ref'] in lookup):
                output.append(obj)
   
    return output

def remove_empty_fields(json_blob):
    """Remove dictionary keys with values of "" or []."""
    for obj in json_blob:
        for key, value in obj.items():
            if value:
                # Loop through internal dictionaries.
                if type(value) is dict:
                    for k, v in list(value.items()):
                        if not v:
                            del obj[key][k]
            else:
                del obj[key]
                
    return json_blob

def transform_text(json_blob, attack_to_name_lookup):
    """Convert [[Citation: foo]] to (Citation: foo), [[Tactic]] to Tactic and {{LinkById|x}} to ID name."""
    tactics = lookup.create_tactics_list()

    for obj in json_blob:
        #try:
        if obj['type'] == 'relationship' and 'description' in obj['attributes']:
            obj['attributes']['description'] = re.sub(' \[\[(Citation:.*?)\]\]', '', obj['attributes']['description'], flags=re.MULTILINE)
            obj['attributes']['description'] = re.sub('\[\[(Citation:.*?)\]\]', '', obj['attributes']['description'], flags=re.MULTILINE)
        else:
            if 'description' in obj['attributes']:
                obj['attributes']['description'] = re.sub('\[\[(Citation:.*?)\]\]', r'(\1)', obj['attributes']['description'], flags=re.MULTILINE)
            if 'x_mitre_detection' in obj['attributes']:
                obj['attributes']['x_mitre_detection'] = re.sub('\[\[(Citation:.*?)\]\]', r'(\1)', obj['attributes']['x_mitre_detection'], flags=re.MULTILINE)
        for tactic in tactics:
            if 'description' in obj['attributes']:
                obj['attributes']['description'] = re.sub('\[\[('+ tactic + ')\]\]', r'\1', obj['attributes']['description'], flags=re.IGNORECASE)
            if 'x_mitre_detection' in obj['attributes']:
                obj['attributes']['x_mitre_detection'] = re.sub('\[\[('+ tactic + ')\]\]', r'\1', obj['attributes']['x_mitre_detection'], flags=re.IGNORECASE)
        if 'description' in obj['attributes']:
            attack_ids = re.findall('\{\{LinkById\|(.*?)\}\}', obj['attributes']['description'])
            for attack_id in attack_ids:
                obj['attributes']['description'] = obj['attributes']['description'].replace('{{LinkById|' + attack_id + '}}', attack_to_name_lookup[attack_id])
        if 'x_mitre_detection' in obj['attributes']:
            attack_ids_detection = re.findall('\{\{LinkById\|(.*?)\}\}', obj['attributes']['x_mitre_detection'])
            for attack_id_detection in attack_ids_detection:
                obj['attributes']['x_mitre_detection'] = obj['attributes']['x_mitre_detection'].replace('{{LinkById|' + attack_id_detection + '}}', attack_to_name_lookup[attack_id])
        if 'external_references' in obj['attributes']:
            for idx, val in enumerate(obj['attributes']['external_references']):
                if 'description' in obj['attributes']['external_references'][idx]:
                    obj['attributes']['external_references'][idx]['description'] = re.sub('\[\[(Citation:.*?)\]\]', r'(\1)', obj['attributes']['external_references'][idx]['description'], flags=re.MULTILINE)


    return json_blob 