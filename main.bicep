param location string = resourceGroup().location
param currentTime string = utcNow()
param appregname string = 'aadtestapp22'
param keyvaulttest string = 'aadexpiration129850'
param logic_app_name string = 'azure-application-notification9'
param connections_keyvault_name string = 'keyvault'
param connections_office365_name string = 'office365'

/* 
Module below references the deployment script and the keyvault creation along with 
the secrets. Access to the KV for the logic app MI was causing issue so added the 
access policy here in the main template by referencing the existing kv created in 
the deployscript and then providing it as the source KV of the access policy
*/

module scriptandkv 'deployscript.bicep' = {
  name: 'scriptandkvdeploy'
  params: {
    currentTime: currentTime
    appregname: appregname
    location: location
    keyvaulttest: keyvaulttest
  }
}


/*
Below creates the actual logic app, based on the brilliant work by Russ Rimmerman,
https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/use-azure-logic-apps-to-notify-of-pending-aad-application-client/ba-p/3014603?fbclid=IwAR3ECopMRsitagEStKLC_yvAmFX4a1Ispn_a8ZFitapPquq9OZcZvQgKVOQ
Did end up making quite a few tweaks to make sure it matches our requirements here at Parallo
Email is no longer sent to each cred/cert owner, only 1 final email to recipient. 
Also made changes so that only about to expire creds/certs are accounted for not the ones
that have already expired. 
*/
resource azure_app_notification 'Microsoft.Logic/workflows@2017-07-01' = {
  name: logic_app_name
  
  identity:{
    type:'SystemAssigned'
  }
  location: location
  properties: {
    state: 'Enabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {
        '$connections': {
          defaultValue: {
          }
          type: 'Object'
        }
      }
      triggers: {
        Recurrence: {
          recurrence: {
            frequency: 'Week'
            interval: 2
            timeZone: 'New Zealand Standard Time'
            startTime: '2022-08-15T10:00:00'
          }
          evaluatedRecurrence: {
            frequency: 'Week'
            interval: 2
            startTime: '2022-08-15T10:00:00'
            timeZone: 'New Zealand Standard Time'
          }
          type: 'Recurrence'
        }
      }
      actions: {
        'Client-id': {
          runAfter: {
            'Tenant-id': [
              'Succeeded'
            ]
          }
          type: 'ApiConnection'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'keyvault\'][\'connectionId\']'
              }
            }
            method: 'get'
            path: '/secrets/@{encodeURIComponent(\'client-id\')}/value'
          }
          runtimeConfiguration: {
            secureData: {
              properties: [
                'inputs'
                'outputs'
              ]
            }
          }
        }
        'Client-secret': {
          runAfter: {
            'Client-id': [
              'Succeeded'
            ]
          }
          type: 'ApiConnection'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'keyvault\'][\'connectionId\']'
              }
            }
            method: 'get'
            path: '/secrets/@{encodeURIComponent(\'client-secret\')}/value'
          }
          runtimeConfiguration: {
            secureData: {
              properties: [
                'inputs'
                'outputs'
              ]
            }
          }
        }
        Close_HTML_tags: {
          runAfter: {
            Until: [
              'Succeeded'
            ]
          }
          type: 'AppendToStringVariable'
          inputs: {
            name: 'html'
            value: '<tbody></table>'
          }
        }
        Get_Auth_Token: {
          runAfter: {
            Initialize_daysTilExpiration: [
              'Succeeded'
            ]
          }
          type: 'Http'
          inputs: {
            body: 'grant_type=client_credentials\n&client_id=@{body(\'Client-id\')?[\'value\']}\n&client_secret=@{body(\'Client-secret\')?[\'value\']}\n&scope=https://graph.microsoft.com/.default'
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded'
            }
            method: 'POST'
            uri: 'https://login.microsoftonline.com/@{body(\'Tenant-id\')?[\'value\']}/oauth2/v2.0/token'
          }
        }
        'Initialize_-_NextLink': {
          runAfter: {
            'Parse_JSON_-_Retrieve_token_Info': [
              'Succeeded'
            ]
          }
          type: 'InitializeVariable'
          inputs: {
            variables: [
              {
                name: 'NextLink'
                type: 'string'
                value: 'https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName,passwordCredentials,keyCredentials&$top=999'
              }
            ]
          }
        }
        'Initialize_-_keyCredential': {
          runAfter: {
            Initialize_passwordCredential: [
              'Succeeded'
            ]
          }
          type: 'InitializeVariable'
          inputs: {
            variables: [
              {
                name: 'keyCredential'
                type: 'array'
              }
            ]
          }
        }
        Initialize_appid: {
          runAfter: {
            'Client-secret': [
              'Succeeded'
            ]
          }
          type: 'InitializeVariable'
          inputs: {
            variables: [
              {
                name: 'AppID'
                type: 'string'
                value: ''
              }
            ]
          }
        }
        Initialize_daysTilExpiration: {
          runAfter: {
            Initialize_html: [
              'Succeeded'
            ]
          }
          type: 'InitializeVariable'
          inputs: {
            variables: [
              {
                name: 'daysTilExpiration'
                type: 'float'
                value: 10
              }
            ]
          }
        }
        Initialize_displayName: {
          runAfter: {
            Initialize_appid: [
              'Succeeded'
            ]
          }
          type: 'InitializeVariable'
          inputs: {
            variables: [
              {
                name: 'displayName'
                type: 'string'
                value: ''
              }
            ]
          }
        }
        Initialize_html: {
          runAfter: {
            Initialize_styles: [
              'Succeeded'
            ]
          }
          type: 'InitializeVariable'
          inputs: {
            variables: [
              {
                name: 'html'
                type: 'string'
                value: '<table  @{variables(\'styles\').tableStyle}><thead><th  @{variables(\'styles\').headerStyle}>Application ID</th><th  @{variables(\'styles\').headerStyle}>Display Name</th><th @{variables(\'styles\').headerStyle}> Key Id</th><th  @{variables(\'styles\').headerStyle}>Days until Expiration</th><th  @{variables(\'styles\').headerStyle}>Type</th><th  @{variables(\'styles\').headerStyle}>Expiration Date</th><th @{variables(\'styles\').headerStyle}>Owner</th></thead><tbody>'
              }
            ]
          }
        }
        Initialize_passwordCredential: {
          runAfter: {
            Initialize_displayName: [
              'Succeeded'
            ]
          }
          type: 'InitializeVariable'
          inputs: {
            variables: [
              {
                name: 'passwordCredential'
                type: 'array'
              }
            ]
          }
        }
        Initialize_styles: {
          runAfter: {
            'Initialize_-_keyCredential': [
              'Succeeded'
            ]
          }
          type: 'InitializeVariable'
          inputs: {
            variables: [
              {
                name: 'styles'
                type: 'object'
                value: {
                  cellStyle: 'style="font-family: Calibri; padding: 5px; border: 1px solid black;"'
                  headerStyle: 'style="font-family: Helvetica; padding: 5px; border: 1px solid black;"'
                  redStyle: 'style="background-color:red; font-family: Calibri; padding: 5px; border: 1px solid black;"'
                  tableStyle: 'style="border-collapse: collapse;"'
                  yellowStyle: 'style="background-color:yellow; font-family: Calibri; padding: 5px; border: 1px solid black;"'
                }
              }
            ]
          }
        }
        'Parse_JSON_-_Retrieve_token_Info': {
          runAfter: {
            Get_Auth_Token: [
              'Succeeded'
            ]
          }
          type: 'ParseJson'
          inputs: {
            content: '@body(\'Get_Auth_Token\')'
            schema: {
              properties: {
                access_token: {
                  type: 'string'
                }
                expires_in: {
                  type: 'integer'
                }
                ext_expires_in: {
                  type: 'integer'
                }
                token_type: {
                  type: 'string'
                }
              }
              type: 'object'
            }
          }
          runtimeConfiguration: {
            secureData: {
              properties: [
                'inputs'
              ]
            }
          }
        }
        Send_the_list_of_applications: {
          runAfter: {
            Close_HTML_tags: [
              'Succeeded'
            ]
          }
          type: 'ApiConnection'
          inputs: {
            body: {
              Body: '<p>@{variables(\'html\')}</p>'
              Importance: 'High'
              Subject: 'List of Secrets and Certificates near expiration'
              To: 'karan.mishra@rhipe.com'
            }
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'office365\'][\'connectionId\']'
              }
            }
            method: 'post'
            path: '/v2/Mail'
          }
          runtimeConfiguration: {
            secureData: {
              properties: [
                'inputs'
                'outputs'
              ]
            }
          }
        }
        'Tenant-id': {
          runAfter: {
          }
          type: 'ApiConnection'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'keyvault\'][\'connectionId\']'
              }
            }
            method: 'get'
            path: '/secrets/@{encodeURIComponent(\'tenant-id\')}/value'
          }
          runtimeConfiguration: {
            secureData: {
              properties: [
                'inputs'
                'outputs'
              ]
            }
          }
        }
        Until: {
          actions: {
            Current_time: {
              runAfter: {
                Get_future_time: [
                  'Succeeded'
                ]
              }
              type: 'Expression'
              kind: 'CurrentTime'
              inputs: {
              }
            }
            'Foreach_-_apps': {
              foreach: '@body(\'Parse_JSON\')?[\'value\']'
              actions: {
                'For_each_-_PasswordCred': {
                  foreach: '@items(\'Foreach_-_apps\')?[\'passwordCredentials\']'
                  actions: {
                    Condition: {
                      actions: {
                        DifferentAsDays: {
                          runAfter: {
                            StartTimeTickValue: [
                              'Succeeded'
                            ]
                          }
                          type: 'Compose'
                          inputs: '@div(div(div(mul(sub(outputs(\'EndTimeTickValue\'),outputs(\'StartTimeTickValue\')),100),1000000000) , 3600), 24)'
                        }
                        EndTimeTickValue: {
                          runAfter: {
                          }
                          type: 'Compose'
                          inputs: '@ticks(item()?[\'endDateTime\'])'
                        }
                        Get_Secret_Owner: {
                          runAfter: {
                            Set_variable: [
                              'Succeeded'
                            ]
                          }
                          type: 'Http'
                          inputs: {
                            headers: {
                              Authorization: 'Bearer @{body(\'Parse_JSON_-_Retrieve_token_Info\')?[\'access_token\']}'
                            }
                            method: 'GET'
                            uri: 'https://graph.microsoft.com/v1.0/applications/@{items(\'Foreach_-_apps\')?[\'id\']}/owners'
                          }
                        }
                        In_Case_of_No_Owner: {
                          actions: {
                            Append_to_string_variable_4: {
                              runAfter: {
                              }
                              type: 'AppendToStringVariable'
                              inputs: {
                                name: 'html'
                                value: '<tr><td @{variables(\'styles\').cellStyle}><a href="https://ms.portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/Credentials/appId/@{variables(\'appId\')}/isMSAApp/">@{variables(\'appId\')}</a></td><td @{variables(\'styles\').cellStyle}>@{variables(\'displayName\')}</td><td @{variables(\'styles\').cellStyle}>@{items(\'For_each_-_PasswordCred\')?[\'keyId\']}</td><td @{if(less(variables(\'daystilexpiration\'),100),variables(\'styles\').redStyle,if(less(variables(\'daystilexpiration\'),150),variables(\'styles\').yellowStyle,variables(\'styles\').cellStyle))}>@{variables(\'daystilexpiration\')} </td><td @{variables(\'styles\').cellStyle}>Secret</td><td @{variables(\'styles\').cellStyle}>@{formatDateTime(item()?[\'endDateTime\'],\'g\')}</td><td @{variables(\'styles\').cellStyle}>No Owner</td></tr>'
                              }
                            }
                          }
                          runAfter: {
                            Get_Secret_Owner: [
                              'Succeeded'
                            ]
                          }
                          else: {
                            actions: {
                              Append_to_string_variable: {
                                runAfter: {
                                }
                                type: 'AppendToStringVariable'
                                inputs: {
                                  name: 'html'
                                  value: '<tr><td @{variables(\'styles\').cellStyle}><a href="https://ms.portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/Credentials/appId/@{variables(\'appId\')}/isMSAApp/">@{variables(\'appId\')}</a></td><td @{variables(\'styles\').cellStyle}>@{variables(\'displayName\')}</td><td @{variables(\'styles\').cellStyle}>@{items(\'For_each_-_PasswordCred\')?[\'keyId\']}</td><td @{if(less(variables(\'daystilexpiration\'),100),variables(\'styles\').redStyle,if(less(variables(\'daystilexpiration\'),150),variables(\'styles\').yellowStyle,variables(\'styles\').cellStyle))}>@{variables(\'daystilexpiration\')} </td><td @{variables(\'styles\').cellStyle}>Secret</td><td @{variables(\'styles\').cellStyle}>@{formatDateTime(item()?[\'endDateTime\'],\'g\')}</td><td @{variables(\'styles\').cellStyle}><a href="mailto:@{body(\'Get_Secret_Owner\')?[\'value\'][0]?[\'userPrincipalName\']}">@{body(\'Get_Secret_Owner\')?[\'value\'][0]?[\'givenName\']} @{body(\'Get_Secret_Owner\')?[\'value\'][0]?[\'surname\']}</a></td></tr>'
                                }
                              }
                            }
                          }
                          expression: {
                            and: [
                              {
                                equals: [
                                  '@length(body(\'Get_Secret_Owner\')?[\'value\'])'
                                  '@int(\'0\')'
                                ]
                              }
                            ]
                          }
                          type: 'If'
                        }
                        Set_variable: {
                          runAfter: {
                            DifferentAsDays: [
                              'Succeeded'
                            ]
                          }
                          type: 'SetVariable'
                          inputs: {
                            name: 'daysTilExpiration'
                            value: '@outputs(\'DifferentAsDays\')'
                          }
                        }
                        StartTimeTickValue: {
                          runAfter: {
                            EndTimeTickValue: [
                              'Succeeded'
                            ]
                          }
                          type: 'Compose'
                          inputs: '@ticks(utcnow())'
                        }
                      }
                      runAfter: {
                      }
                      expression: {
                        and: [
                          {
                            greaterOrEquals: [
                              '@body(\'Get_future_time\')'
                              '@items(\'For_each_-_PasswordCred\')?[\'endDateTime\']'
                            ]
                          }
                          {
                            greater: [
                              '@items(\'For_each_-_PasswordCred\')?[\'endDateTime\']'
                              '@body(\'Current_time\')'
                            ]
                          }
                        ]
                      }
                      type: 'If'
                    }
                  }
                  runAfter: {
                    'Set_variable_-_keyCredential': [
                      'Succeeded'
                    ]
                  }
                  type: 'Foreach'
                }
                For_each_KeyCred: {
                  foreach: '@items(\'Foreach_-_apps\')?[\'keyCredentials\']'
                  actions: {
                    Condition_2: {
                      actions: {
                        Condition_5: {
                          actions: {
                            Append_Certificate_to_HTML_without_owner: {
                              runAfter: {
                              }
                              type: 'AppendToStringVariable'
                              inputs: {
                                name: 'html'
                                value: '<tr><td @{variables(\'styles\').cellStyle}><a href="https://ms.portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/Credentials/appId/@{variables(\'appId\')}/isMSAApp/">@{variables(\'appId\')}</a></td><td @{variables(\'styles\').cellStyle}>@{variables(\'displayName\')}</td><td @{variables(\'styles\').cellStyle}>@{items(\'For_each_KeyCred\')?[\'keyId\']}</td><td @{if(less(variables(\'daystilexpiration\'), 15), variables(\'styles\').redStyle, if(less(variables(\'daystilexpiration\'), 30), variables(\'styles\').yellowStyle, variables(\'styles\').cellStyle))}>@{variables(\'daystilexpiration\')} </td><td @{variables(\'styles\').cellStyle}>Certificate</td><td @{variables(\'styles\').cellStyle}>@{formatDateTime(item()?[\'endDateTime\'], \'g\')}</td><td @{variables(\'styles\').cellStyle}>No Owner</td></tr>'
                              }
                            }
                          }
                          runAfter: {
                            Get_Certificate_Owner: [
                              'Succeeded'
                            ]
                          }
                          else: {
                            actions: {
                              Append_Certificate_to_HTML_with_owner: {
                                runAfter: {
                                }
                                type: 'AppendToStringVariable'
                                inputs: {
                                  name: 'html'
                                  value: '<tr><td @{variables(\'styles\').cellStyle}><a href="https://ms.portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/Credentials/appId/@{variables(\'appId\')}/isMSAApp/">@{variables(\'appId\')}</a></td><td @{variables(\'styles\').cellStyle}>@{variables(\'displayName\')}</td><td @{variables(\'styles\').cellStyle}>@{items(\'For_each_KeyCred\')?[\'keyId\']}</td><td @{if(less(variables(\'daystilexpiration\'), 15), variables(\'styles\').redStyle, if(less(variables(\'daystilexpiration\'), 30), variables(\'styles\').yellowStyle, variables(\'styles\').cellStyle))}>@{variables(\'daystilexpiration\')} </td><td @{variables(\'styles\').cellStyle}>Certificate</td><td @{variables(\'styles\').cellStyle}>@{formatDateTime(item()?[\'endDateTime\'], \'g\')}</td><td @{variables(\'styles\').cellStyle}><a href="mailto:@{body(\'Get_Certificate_Owner\')?[\'value\'][0]?[\'userPrincipalName\']}">@{body(\'Get_Certificate_Owner\')?[\'value\'][0]?[\'givenName\']} @{body(\'Get_Certificate_Owner\')?[\'value\'][0]?[\'surname\']}</a></td></tr>'
                                }
                              }
                            }
                          }
                          expression: {
                            and: [
                              {
                                equals: [
                                  '@length(body(\'Get_Certificate_Owner\')?[\'value\'])'
                                  '@int(\'0\')'
                                ]
                              }
                            ]
                          }
                          type: 'If'
                        }
                        DifferentAsDays2: {
                          runAfter: {
                            StartTimeTickValue2: [
                              'Succeeded'
                            ]
                          }
                          type: 'Compose'
                          inputs: '@div(div(div(mul(sub(outputs(\'EndTimeTickValue2\'),outputs(\'StartTimeTickValue2\')),100),1000000000) , 3600), 24)'
                        }
                        EndTimeTickValue2: {
                          runAfter: {
                          }
                          type: 'Compose'
                          inputs: '@ticks(item()?[\'endDateTime\'])'
                        }
                        Get_Certificate_Owner: {
                          runAfter: {
                            Store_Days_till_expiration: [
                              'Succeeded'
                            ]
                          }
                          type: 'Http'
                          inputs: {
                            headers: {
                              Authorization: 'Bearer @{body(\'Parse_JSON_-_Retrieve_token_Info\')?[\'access_token\']}'
                            }
                            method: 'GET'
                            uri: 'https://graph.microsoft.com/v1.0/applications/@{items(\'Foreach_-_apps\')?[\'id\']}/owners'
                          }
                        }
                        StartTimeTickValue2: {
                          runAfter: {
                            EndTimeTickValue2: [
                              'Succeeded'
                            ]
                          }
                          type: 'Compose'
                          inputs: '@ticks(utcnow())'
                        }
                        Store_Days_till_expiration: {
                          runAfter: {
                            DifferentAsDays2: [
                              'Succeeded'
                            ]
                          }
                          type: 'SetVariable'
                          inputs: {
                            name: 'daysTilExpiration'
                            value: '@outputs(\'DifferentAsDays2\')'
                          }
                        }
                      }
                      runAfter: {
                      }
                      expression: {
                        and: [
                          {
                            greaterOrEquals: [
                              '@body(\'Get_future_time\')'
                              '@items(\'For_each_KeyCred\')?[\'endDateTime\']'
                            ]
                          }
                          {
                            greaterOrEquals: [
                              '@items(\'For_each_KeyCred\')?[\'endDateTime\']'
                              '@body(\'Current_time\')'
                            ]
                          }
                        ]
                      }
                      type: 'If'
                    }
                  }
                  runAfter: {
                    'For_each_-_PasswordCred': [
                      'Succeeded'
                    ]
                  }
                  type: 'Foreach'
                }
                'Set_variable_-_appId': {
                  runAfter: {
                  }
                  type: 'SetVariable'
                  inputs: {
                    name: 'AppID'
                    value: '@items(\'Foreach_-_apps\')?[\'appId\']'
                  }
                }
                'Set_variable_-_displayName': {
                  runAfter: {
                    'Set_variable_-_appId': [
                      'Succeeded'
                    ]
                  }
                  type: 'SetVariable'
                  inputs: {
                    name: 'displayName'
                    value: '@items(\'Foreach_-_apps\')?[\'displayName\']'
                  }
                }
                'Set_variable_-_keyCredential': {
                  runAfter: {
                    'Set_variable_-_passwordCredential': [
                      'Succeeded'
                    ]
                  }
                  type: 'SetVariable'
                  inputs: {
                    name: 'keyCredential'
                    value: '@items(\'Foreach_-_apps\')?[\'keyCredentials\']'
                  }
                }
                'Set_variable_-_passwordCredential': {
                  runAfter: {
                    'Set_variable_-_displayName': [
                      'Succeeded'
                    ]
                  }
                  type: 'SetVariable'
                  inputs: {
                    name: 'passwordCredential'
                    value: '@items(\'Foreach_-_apps\')?[\'passwordCredentials\']'
                  }
                }
              }
              runAfter: {
                Current_time: [
                  'Succeeded'
                ]
              }
              type: 'Foreach'
              runtimeConfiguration: {
                concurrency: {
                  repetitions: 1
                }
              }
            }
            Get_future_time: {
              runAfter: {
                Parse_JSON: [
                  'Succeeded'
                ]
              }
              type: 'Expression'
              kind: 'GetFutureTime'
              inputs: {
                interval: 91
                timeUnit: 'Day'
              }
            }
            'HTTP_-_Get_AzureAD_Applications': {
              runAfter: {
              }
              type: 'Http'
              inputs: {
                headers: {
                  Authorization: 'Bearer @{body(\'Parse_JSON_-_Retrieve_token_Info\')?[\'access_token\']}'
                }
                method: 'GET'
                uri: '@variables(\'NextLink\')'
              }
            }
            Parse_JSON: {
              runAfter: {
                'HTTP_-_Get_AzureAD_Applications': [
                  'Succeeded'
                ]
              }
              type: 'ParseJson'
              inputs: {
                content: '@body(\'HTTP_-_Get_AzureAD_Applications\')'
                schema: {
                  properties: {
                    properties: {
                      properties: {
                        '@@odata.context': {
                          properties: {
                            type: {
                              type: 'string'
                            }
                          }
                          type: 'object'
                        }
                        value: {
                          properties: {
                            items: {
                              properties: {
                                properties: {
                                  properties: {
                                    '@@odata.id': {
                                      properties: {
                                        type: {
                                          type: 'string'
                                        }
                                      }
                                      type: 'object'
                                    }
                                    appId: {
                                      properties: {
                                        type: {
                                          type: 'string'
                                        }
                                      }
                                      type: 'object'
                                    }
                                    displayName: {
                                      properties: {
                                        type: {
                                          type: 'string'
                                        }
                                      }
                                      type: 'object'
                                    }
                                    keyCredentials: {
                                      properties: {
                                        type: {
                                          type: 'string'
                                        }
                                      }
                                      type: 'object'
                                    }
                                    passwordCredentials: {
                                      properties: {
                                        items: {
                                          properties: {
                                            properties: {
                                              properties: {
                                                customKeyIdentifier: {
                                                  properties: {
                                                  }
                                                  type: 'object'
                                                }
                                                displayName: {
                                                  properties: {
                                                    type: {
                                                      type: 'string'
                                                    }
                                                  }
                                                  type: 'object'
                                                }
                                                endDateTime: {
                                                  properties: {
                                                    type: {
                                                      type: 'string'
                                                    }
                                                  }
                                                  type: 'object'
                                                }
                                                hint: {
                                                  properties: {
                                                    type: {
                                                      type: 'string'
                                                    }
                                                  }
                                                  type: 'object'
                                                }
                                                keyId: {
                                                  properties: {
                                                    type: {
                                                      type: 'string'
                                                    }
                                                  }
                                                  type: 'object'
                                                }
                                                secretText: {
                                                  properties: {
                                                  }
                                                  type: 'object'
                                                }
                                                startDateTime: {
                                                  properties: {
                                                    type: {
                                                      type: 'string'
                                                    }
                                                  }
                                                  type: 'object'
                                                }
                                              }
                                              type: 'object'
                                            }
                                            required: {
                                              items: {
                                                type: 'string'
                                              }
                                              type: 'array'
                                            }
                                            type: {
                                              type: 'string'
                                            }
                                          }
                                          type: 'object'
                                        }
                                        type: {
                                          type: 'string'
                                        }
                                      }
                                      type: 'object'
                                    }
                                  }
                                  type: 'object'
                                }
                                required: {
                                  items: {
                                    type: 'string'
                                  }
                                  type: 'array'
                                }
                                type: {
                                  type: 'string'
                                }
                              }
                              type: 'object'
                            }
                            type: {
                              type: 'string'
                            }
                          }
                          type: 'object'
                        }
                      }
                      type: 'object'
                    }
                    type: {
                      type: 'string'
                    }
                  }
                  type: 'object'
                }
              }
            }
            Update_Next_Link: {
              runAfter: {
                'Foreach_-_apps': [
                  'Succeeded'
                ]
              }
              type: 'SetVariable'
              inputs: {
                name: 'NextLink'
                value: '@{body(\'Parse_JSON\')?[\'@odata.nextLink\']}'
              }
            }
          }
          runAfter: {
            'Initialize_-_NextLink': [
              'Succeeded'
            ]
          }
          expression: '@not(equals(variables(\'NextLink\'), null))'
          limit: {
            count: 60
            timeout: 'PT1H'
          }
          type: 'Until'
        }
      }
      outputs: {
      }
    }
    parameters: {
      '$connections': {
        value: {
          keyvault: {
            connectionId: connections_keyvault_name_resource.id
            connectionName: connections_keyvault_name
            connectionProperties: {
              authentication: {
                  type: 'ManagedServiceIdentity'
              }
          }
            id: reference('Microsoft.Web/connections/keyvault', '2016-06-01').api.id
          }
          office365: {
            connectionId: connections_office365_name_resource.id
            connectionName: connections_office365_name
            id: reference('Microsoft.Web/connections/office365', '2016-06-01').api.id
          }
        }
      }
    }
  }
}

/*
Below references the key vault being created in the deployscript
*/
resource kv 'Microsoft.KeyVault/vaults@2019-09-01' existing = {
  name: keyvaulttest
}
/*
below uses the above reference and adds an access policy so MI of the logic app
can access the secrets stored in the KV
*/
resource keyVaultAccessPolicy 'Microsoft.KeyVault/vaults/accessPolicies@2021-06-01-preview' = {
  name: '${kv.name}/add'
  properties: {
      accessPolicies: [
          {
              tenantId: tenant().tenantId
              objectId: azure_app_notification.identity.principalId
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
  }
}

/*
Below are the 2 API connections, first uses the MI of the logic app to connect to 
the key vault as it was given access by the policy above
*/

resource connections_keyvault_name_resource 'Microsoft.Web/connections@2016-06-01' = {
  name: connections_keyvault_name
  location: location
  kind: 'V1'
  properties: {
    displayName: 'kv'
    
    api: {
      name: connections_keyvault_name
      displayName: 'Azure Key Vault'
      description: 'Azure Key Vault is a service to securely store and access secrets.'
      id: '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Web/locations/${location}/managedApis/keyvault'
      type: 'Microsoft.Web/locations/managedApis'
    }
    parameterValueType: 'Alternative'
    alternativeParameterValues: {
      vaultName: keyvaulttest
    }
    }
  }
/*
THis is the office365 API connection that needs to be authenticated so it can
send out the email, Matt had a great suggestion to use send grid for this, might
be worth having a SendGrid account for parallo that can be used for this
and in the future for sending emails at scale
*/

resource connections_office365_name_resource 'Microsoft.Web/connections@2016-06-01' = {
  name: connections_office365_name
  location: location
  kind: 'V1'
  properties: {
    displayName: connections_office365_name
    api: {
      name: connections_office365_name
      displayName: 'Office 365 Outlook'
      description: 'Microsoft Office 365 is a cloud-based service that is designed to help meet your organization\'s needs for robust security, reliability, and user productivity.'
      iconUri: 'https://connectoricons-prod.azureedge.net/releases/v1.0.1588/1.0.1588.2938/${connections_office365_name}/icon.png'
      brandColor: '#0078D4'
      id: '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Web/locations/${location}/managedApis/${connections_office365_name}'
      type: 'Microsoft.Web/locations/managedApis'
    }
    
  }
}
