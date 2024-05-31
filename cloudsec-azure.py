from azure.identity import ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.authorization.models import RoleAssignmentProperties
import json

def extract_azure_identities():
    json_file_path = 'auth.json'
    with open(json_file_path, 'r') as file:
        data = json.load(file)
    
    azure_identities = []
    
    for provider in data['cloudProviders']:
        if provider['name'] == 'Azure':
            for identity in provider['identities']:
                identity_info = {
                    "type": identity.get('type'),
                    "client_Id": identity.get('client_Id'),
                    "tenant_id": identity.get('tenant_id'),
                    "client_secret": identity.get('client_secret'),
                    "subscriptionId": identity.get('subscription_id')
                }
                # Remove keys with None values
                identity_info = {k: v for k, v in identity_info.items() if v is not None}
                azure_identities.append(identity_info)
    
    return azure_identities

def list_role_assignments(subscription_id, credential):
    # Create an Authorization Management client
    auth_client = AuthorizationManagementClient(credential, subscription_id)
    
    # Define the scope of the subscription
    scope = f"/subscriptions/{subscription_id}"
    
    # List all role assignments in the subscription
    role_assignments = auth_client.role_assignments.list_for_scope(scope)
    return role_assignments

def get_role_definitions(subscription_id, credential):
    # Create an Authorization Management client
    auth_client = AuthorizationManagementClient(credential, subscription_id)
    
    # List all role definitions in the subscription
    scope = f"/subscriptions/{subscription_id}"
    role_definitions = auth_client.role_definitions.list(scope)
    
    # Create a dictionary to map role definition IDs to role names
    role_definitions_dict = {role.id.split('/')[-1]: role.role_name for role in role_definitions}
    return role_definitions_dict


if __name__ == '__main__':
    # Get Azure credentials from auth.json file
    azure_identities = extract_azure_identities()
    subscription_id = azure_identities[0].get('subscriptionId')
    tenant_id = azure_identities[0].get('tenant_id')
    client_id = azure_identities[0].get('client_Id')
    client_secret = azure_identities[0].get('client_secret')

    # Create a service principal credential
    credential = ClientSecretCredential(tenant_id=tenant_id, client_id=client_id, client_secret=client_secret)

    # Create a resource management client and list resources
    auth_client = AuthorizationManagementClient(credential, subscription_id)
    role_assignment_client = AuthorizationManagementClient(credential, subscription_id)
    resource_client = ResourceManagementClient(credential, subscription_id)
    
    # List role assignments and get role definitions
    role_assignments = list_role_assignments(subscription_id, credential)
    role_definitions_dict = get_role_definitions(subscription_id, credential)

    print("Role Assignments for Service Principal:")
    for assignment in role_assignments:
        principal_id = assignment.principal_id
        role_definition_id = assignment.role_definition_id.split('/')[-1]  # Extract the role definition ID
        scope = assignment.scope
        role_name = role_definitions_dict.get(role_definition_id, "Unknown Role")
        print(f"Principal ID: {principal_id}, Role: {role_name}, Scope: {scope}")

    # Print resource details
    resources = resource_client.resources.list()
    for resource in resources:
        if resource.type == 'Microsoft.Compute/virtualMachines' or resource.type == 'Microsoft.KeyVault/vaults':
            print(f"Resource Type: {resource.type}")
            print(f"Resource ID: {resource.id}")
            print(f"Resource Name: {resource.name}")
            print(f"Resource Location: {resource.location}")
            print()

           