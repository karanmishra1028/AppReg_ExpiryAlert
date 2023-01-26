/*This deployment script creates an app reg in the tenant that has a application read all permission assigned to it.
The deoployment script requires a user managed identity to run the script (AppRegCreator in the RG called 'app-reg-automation' as in the below script) 
The managed identity is created before hand and has a custom azure role required to create dependencies required for the deployment and has AAD role
of Application administrator to be able to create the application registration in the tenant. The container instance and storage account created
are deleted as part of the clean up when the script succeeds. 

*/

param location string
param appregname string
param currentTime string
param keyvaulttest string

resource script 'Microsoft.Resources/deploymentScripts@2019-10-01-preview' = {
  name: appregname
  location: location
  kind: 'AzurePowerShell'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${resourceId('app-reg-automation', 'Microsoft.ManagedIdentity/userAssignedIdentities', 'AppRegCreator')}': {}
    }
  }
  properties: {
    azPowerShellVersion: '5.0'
    arguments: '-resourceName "${appregname}"'
    scriptContent: '''
      param([string] $resourceName)
      $token = (Get-AzAccessToken -ResourceUrl https://graph.microsoft.com).Token
      $headers = @{'Content-Type' = 'application/json'; 'Authorization' = 'Bearer ' + $token}

      $template = @{
        displayName = $resourceName
        requiredResourceAccess = @(
          @{
            resourceAppId = "00000003-0000-0000-c000-000000000000"
            resourceAccess = @(
              @{
                id = "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"
                type = "Role"
              }
            )
          }
        )
        signInAudience = "AzureADMyOrg"
      }
      
      $app = (Invoke-RestMethod -Method Get -Headers $headers -Uri "https://graph.microsoft.com/beta/applications?filter=displayName eq '$($resourceName)'").value
      $principal = @{}
      if ($app) {
        $ignore = Invoke-RestMethod -Method Patch -Headers $headers -Uri "https://graph.microsoft.com/beta/applications/$($app.id)" -Body ($template | ConvertTo-Json -Depth 10)
        $principal = (Invoke-RestMethod -Method Get -Headers $headers -Uri "https://graph.microsoft.com/beta/servicePrincipals?filter=appId eq '$($app.appId)'").value
      } else {
        $app = (Invoke-RestMethod -Method Post -Headers $headers -Uri "https://graph.microsoft.com/beta/applications" -Body ($template | ConvertTo-Json -Depth 10))
        $principal = Invoke-RestMethod -Method POST -Headers $headers -Uri  "https://graph.microsoft.com/beta/servicePrincipals" -Body (@{ "appId" = $app.appId } | ConvertTo-Json)
      }
      
      $app = (Invoke-RestMethod -Method Get -Headers $headers -Uri "https://graph.microsoft.com/beta/applications/$($app.id)")
      
      foreach ($password in $app.passwordCredentials) {
        Write-Host "Deleting secret with id: $($password.keyId)"
        $body = @{
          "keyId" = $password.keyId
        }
        $ignore = Invoke-RestMethod -Method POST -Headers $headers -Uri "https://graph.microsoft.com/beta/applications/$($app.id)/removePassword" -Body ($body | ConvertTo-Json)
      }
      
      $body = @{
        "passwordCredential" = @{
          "displayName"= "Client Secret"
        }
      }
      $secret = (Invoke-RestMethod -Method POST -Headers $headers -Uri  "https://graph.microsoft.com/beta/applications/$($app.id)/addPassword" -Body ($body | ConvertTo-Json)).secretText
      
      $DeploymentScriptOutputs = @{}
      $DeploymentScriptOutputs['objectId'] = $app.id
      $DeploymentScriptOutputs['clientId'] = $app.appId
      $DeploymentScriptOutputs['clientSecret'] = $secret
      $DeploymentScriptOutputs['principalId'] = $principal.id

    '''
    cleanupPreference: 'OnSuccess'
    retentionInterval: 'P1D'
    forceUpdateTag: currentTime 
  }
}

output objectId string = script.properties.outputs.objectId
output clientId string = script.properties.outputs.clientId
var clientSecret = script.properties.outputs.clientSecret
output principalId string = script.properties.outputs.principalId


/*
The above outputs from the deplyment script are fed as inputs to the
keyvault created below, 
notice I changed clientsecret from output to a variable as it was showing up
as plain text in the output of the deployment which kind of defeats the purpose
of storing it in a keyvault. One access policy exists for my object ID in my tenant that
is hardcoded, remove that and add object id of a group that has all CPM engineers perhaps?
*/
resource keyVault 'Microsoft.KeyVault/vaults@2019-09-01' = {
  name: keyvaulttest
  location: location
  properties: {
    enabledForDeployment: true
    enabledForTemplateDeployment: true
    enabledForDiskEncryption: false
    tenantId: tenant().tenantId
    accessPolicies: [
      {
        tenantId: tenant().tenantId
        objectId: 'abada16c-0344-4877-9d0e-fa4c6d0fd4a1'
        permissions: {
          keys: [
            'get'
          ]
          secrets: [
            'list'
            'get'
          ]
        }
      }
    ]
    sku: {
      name: 'standard'
      family: 'A'
    }
  }
}

/*
Below are the secrets being created in the above KV
*/

resource tenantidSecret 'Microsoft.KeyVault/vaults/secrets@2019-09-01' = {
  name: '${keyvaulttest}/tenant-id'
  dependsOn:[
    keyVault
  ]
  properties: {
    value: tenant().tenantId
  }
}

resource clientidSecret 'Microsoft.KeyVault/vaults/secrets@2019-09-01' = {
  name: '${keyvaulttest}/client-id'
  dependsOn:[
    keyVault
  ]
  properties: {
    value: script.properties.outputs.clientId
  }
}
resource clientsecretSecret 'Microsoft.KeyVault/vaults/secrets@2019-09-01' = {
  name: '${keyvaulttest}/client-secret'
  dependsOn: [
    keyVault
  ]
  properties: {
    value: clientSecret
  }
}
