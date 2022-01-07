[comment]: # "Auto-generated SOAR connector documentation"
# F5 BIG\-IP LTM

Publisher: Splunk  
Connector Version: 2\.0\.6  
Product Vendor: F5  
Product Name: Local Traffic Manager  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.6\.19142  

This app implements investigate and generic actions to integrate with an F5 BIG\-IP LTM instance to manage pools and nodes

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Local Traffic Manager asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base\_url** |  required  | string | Base URL of F5 BIG\-IP LTM instance \(e\.g\. https\://10\.1\.16\.110\)
**username** |  required  | string | User name
**password** |  required  | password | Password
**verify\_server\_cert** |  optional  | boolean | Verify Server SSL certificate

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using the supplied configuration  
[create node](#action-create-node) - Create a new node  
[delete node](#action-delete-node) - Delete a node  
[remove node](#action-remove-node) - Remove a node from a pool  
[create pool](#action-create-pool) - Create a new pool  
[add node](#action-add-node) - Add an existing node to a pool  
[disable node](#action-disable-node) - Disable a node  
[enable node](#action-enable-node) - Enable a node  
[describe node](#action-describe-node) - Get information about a node  
[get node stats](#action-get-node-stats) - Get stats of the node  
[list nodes](#action-list-nodes) - Fetch a list of nodes \(if no value is provided, all nodes will be returned\)  
[list pools](#action-list-pools) - Fetch a list of configured pools \(if no value is provided, all pools will be returned\)  
[list members](#action-list-members) - Fetch a list of configured node members of a pool \(if no value is provided, all node members of a pool will be returned\)  

## action: 'test connectivity'
Validate the asset configuration for connectivity using the supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'create node'
Create a new node

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**node\_name** |  required  | Name of the node to create | string |  `f5 node name` 
**partition\_name** |  required  | Name of the partition | string |  `f5 partition name` 
**ip\_address** |  required  | IP address of the new node | string |  `ip`  `ipv6` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip\_address | string |  `ip`  `ipv6` 
action\_result\.parameter\.node\_name | string |  `f5 node name` 
action\_result\.parameter\.partition\_name | string |  `f5 partition name` 
action\_result\.data\.\*\.address | string |  `ip` 
action\_result\.data\.\*\.connectionLimit | numeric | 
action\_result\.data\.\*\.dynamicRatio | numeric | 
action\_result\.data\.\*\.ephemeral | string | 
action\_result\.data\.\*\.fqdn\.addressFamily | string | 
action\_result\.data\.\*\.fqdn\.autopopulate | string | 
action\_result\.data\.\*\.fqdn\.downInterval | numeric | 
action\_result\.data\.\*\.fqdn\.interval | string | 
action\_result\.data\.\*\.fullPath | string | 
action\_result\.data\.\*\.generation | numeric | 
action\_result\.data\.\*\.kind | string | 
action\_result\.data\.\*\.logging | string | 
action\_result\.data\.\*\.monitor | string | 
action\_result\.data\.\*\.name | string |  `f5 node name` 
action\_result\.data\.\*\.partition | string |  `f5 partition name` 
action\_result\.data\.\*\.rateLimit | string | 
action\_result\.data\.\*\.ratio | numeric | 
action\_result\.data\.\*\.selfLink | string |  `url` 
action\_result\.data\.\*\.session | string | 
action\_result\.data\.\*\.state | string | 
action\_result\.summary\.node\_name | string |  `f5 node name` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete node'
Delete a node

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**node\_name** |  required  | Name of the node to delete | string |  `f5 node name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.node\_name | string |  `f5 node name` 
action\_result\.data | string | 
action\_result\.summary\.node\_name | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'remove node'
Remove a node from a pool

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**node\_name** |  required  | Name of the node to remove | string |  `f5 node name` 
**port** |  required  | Port number | string |  `port` 
**pool\_name** |  required  | Name of the pool to remove the node from | string |  `f5 pool name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.node\_name | string |  `f5 node name` 
action\_result\.parameter\.pool\_name | string |  `f5 pool name` 
action\_result\.parameter\.port | string |  `port` 
action\_result\.data | string | 
action\_result\.summary\.node\_name | string |  `f5 node name` 
action\_result\.summary\.pool\_name | string |  `f5 pool name` 
action\_result\.summary\.port | string |  `port` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'create pool'
Create a new pool

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**pool\_name** |  required  | Name of the pool to create | string |  `f5 pool name` 
**pool\_description** |  optional  | Description of the pool | string | 
**partition\_name** |  required  | Name of the partition | string |  `f5 partition name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.partition\_name | string |  `f5 partition name` 
action\_result\.parameter\.pool\_description | string | 
action\_result\.parameter\.pool\_name | string |  `f5 pool name` 
action\_result\.data\.\*\.allowNat | string | 
action\_result\.data\.\*\.allowSnat | string | 
action\_result\.data\.\*\.fullPath | string | 
action\_result\.data\.\*\.generation | numeric | 
action\_result\.data\.\*\.ignorePersistedWeight | string | 
action\_result\.data\.\*\.ipTosToClient | string | 
action\_result\.data\.\*\.ipTosToServer | string | 
action\_result\.data\.\*\.kind | string | 
action\_result\.data\.\*\.linkQosToClient | string | 
action\_result\.data\.\*\.linkQosToServer | string | 
action\_result\.data\.\*\.loadBalancingMode | string | 
action\_result\.data\.\*\.membersReference\.isSubcollection | boolean | 
action\_result\.data\.\*\.membersReference\.link | string |  `url` 
action\_result\.data\.\*\.minActiveMembers | numeric | 
action\_result\.data\.\*\.minUpMembers | numeric | 
action\_result\.data\.\*\.minUpMembersAction | string | 
action\_result\.data\.\*\.minUpMembersChecking | string | 
action\_result\.data\.\*\.name | string |  `f5 pool name` 
action\_result\.data\.\*\.partition | string |  `f5 partition name` 
action\_result\.data\.\*\.queueDepthLimit | numeric | 
action\_result\.data\.\*\.queueOnConnectionLimit | string | 
action\_result\.data\.\*\.queueTimeLimit | numeric | 
action\_result\.data\.\*\.reselectTries | numeric | 
action\_result\.data\.\*\.selfLink | string |  `url` 
action\_result\.data\.\*\.serviceDownAction | string | 
action\_result\.data\.\*\.slowRampTime | numeric | 
action\_result\.summary\.partition | string |  `f5 partition name` 
action\_result\.summary\.pool\_description | string | 
action\_result\.summary\.pool\_name | string |  `f5 pool name` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'add node'
Add an existing node to a pool

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**node\_name** |  required  | Name of the node to add | string |  `f5 node name` 
**partition\_name** |  required  | Name of the partition to add node | string |  `f5 partition name` 
**port** |  required  | Port number | string |  `port` 
**pool\_name** |  required  | Name of the pool to add node member | string |  `f5 pool name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.node\_name | string |  `f5 node name` 
action\_result\.parameter\.partition\_name | string |  `f5 partition name` 
action\_result\.parameter\.pool\_name | string |  `f5 pool name` 
action\_result\.parameter\.port | string |  `port` 
action\_result\.data\.\*\.address | string |  `ip` 
action\_result\.data\.\*\.connectionLimit | numeric | 
action\_result\.data\.\*\.dynamicRatio | numeric | 
action\_result\.data\.\*\.ephemeral | string | 
action\_result\.data\.\*\.fqdn\.autopopulate | string | 
action\_result\.data\.\*\.fullPath | string | 
action\_result\.data\.\*\.generation | numeric | 
action\_result\.data\.\*\.inheritProfile | string | 
action\_result\.data\.\*\.kind | string | 
action\_result\.data\.\*\.logging | string | 
action\_result\.data\.\*\.monitor | string | 
action\_result\.data\.\*\.name | string |  `f5 node name` 
action\_result\.data\.\*\.partition | string |  `f5 partition name` 
action\_result\.data\.\*\.priorityGroup | numeric | 
action\_result\.data\.\*\.rateLimit | string | 
action\_result\.data\.\*\.ratio | numeric | 
action\_result\.data\.\*\.selfLink | string |  `url` 
action\_result\.data\.\*\.session | string | 
action\_result\.data\.\*\.state | string | 
action\_result\.summary\.node\_name | string | 
action\_result\.summary\.pool\_name | string |  `f5 pool name` 
action\_result\.summary\.port | string |  `port` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'disable node'
Disable a node

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**node\_name** |  required  | Name of the node to disable | string |  `f5 node name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.node\_name | string |  `f5 node name` 
action\_result\.data\.\*\.address | string |  `ip` 
action\_result\.data\.\*\.connectionLimit | numeric | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.dynamicRatio | numeric | 
action\_result\.data\.\*\.ephemeral | string | 
action\_result\.data\.\*\.fqdn\.addressFamily | string | 
action\_result\.data\.\*\.fqdn\.autopopulate | string | 
action\_result\.data\.\*\.fqdn\.downInterval | numeric | 
action\_result\.data\.\*\.fqdn\.interval | string | 
action\_result\.data\.\*\.fullPath | string | 
action\_result\.data\.\*\.generation | numeric | 
action\_result\.data\.\*\.kind | string | 
action\_result\.data\.\*\.logging | string | 
action\_result\.data\.\*\.monitor | string | 
action\_result\.data\.\*\.name | string |  `f5 node name` 
action\_result\.data\.\*\.rateLimit | string | 
action\_result\.data\.\*\.ratio | numeric | 
action\_result\.data\.\*\.selfLink | string |  `url` 
action\_result\.data\.\*\.session | string | 
action\_result\.data\.\*\.state | string | 
action\_result\.summary\.node\_name | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'enable node'
Enable a node

Type: **correct**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**node\_name** |  required  | Name of the node to enable | string |  `f5 node name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.node\_name | string |  `f5 node name` 
action\_result\.data\.\*\.address | string |  `ip` 
action\_result\.data\.\*\.connectionLimit | numeric | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.dynamicRatio | numeric | 
action\_result\.data\.\*\.ephemeral | string | 
action\_result\.data\.\*\.fqdn\.addressFamily | string | 
action\_result\.data\.\*\.fqdn\.autopopulate | string | 
action\_result\.data\.\*\.fqdn\.downInterval | numeric | 
action\_result\.data\.\*\.fqdn\.interval | string | 
action\_result\.data\.\*\.fullPath | string | 
action\_result\.data\.\*\.generation | numeric | 
action\_result\.data\.\*\.kind | string | 
action\_result\.data\.\*\.logging | string | 
action\_result\.data\.\*\.monitor | string | 
action\_result\.data\.\*\.name | string |  `f5 node name` 
action\_result\.data\.\*\.rateLimit | string | 
action\_result\.data\.\*\.ratio | numeric | 
action\_result\.data\.\*\.selfLink | string |  `url` 
action\_result\.data\.\*\.session | string | 
action\_result\.data\.\*\.state | string | 
action\_result\.summary\.node\_name | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'describe node'
Get information about a node

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**node\_name** |  required  | Name of the node to describe | string |  `f5 node name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.node\_name | string |  `f5 node name` 
action\_result\.data\.\*\.address | string |  `ip` 
action\_result\.data\.\*\.connectionLimit | numeric | 
action\_result\.data\.\*\.dynamicRatio | numeric | 
action\_result\.data\.\*\.ephemeral | string | 
action\_result\.data\.\*\.fqdn\.addressFamily | string | 
action\_result\.data\.\*\.fqdn\.autopopulate | string | 
action\_result\.data\.\*\.fqdn\.downInterval | numeric | 
action\_result\.data\.\*\.fqdn\.interval | string | 
action\_result\.data\.\*\.fullPath | string | 
action\_result\.data\.\*\.generation | numeric | 
action\_result\.data\.\*\.kind | string | 
action\_result\.data\.\*\.logging | string | 
action\_result\.data\.\*\.monitor | string | 
action\_result\.data\.\*\.name | string |  `f5 node name` 
action\_result\.data\.\*\.rateLimit | string | 
action\_result\.data\.\*\.ratio | numeric | 
action\_result\.data\.\*\.selfLink | string |  `url` 
action\_result\.data\.\*\.session | string | 
action\_result\.data\.\*\.state | string | 
action\_result\.summary\.state | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get node stats'
Get stats of the node

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**node\_name** |  required  | Name of the node | string |  `f5 node name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.node\_name | string |  `f5 node name` 
action\_result\.data\.\*\.addr\.description | string | 
action\_result\.data\.\*\.curSessions\.value | numeric | 
action\_result\.data\.\*\.monitorRule\.description | string | 
action\_result\.data\.\*\.monitorStatus\.description | string | 
action\_result\.data\.\*\.serverside\_bitsIn\.value | numeric | 
action\_result\.data\.\*\.serverside\_bitsOut\.value | numeric | 
action\_result\.data\.\*\.serverside\_curConns\.value | numeric | 
action\_result\.data\.\*\.serverside\_maxConns\.value | numeric | 
action\_result\.data\.\*\.serverside\_pktsIn\.value | numeric | 
action\_result\.data\.\*\.serverside\_pktsOut\.value | numeric | 
action\_result\.data\.\*\.serverside\_totConns\.value | numeric | 
action\_result\.data\.\*\.sessionStatus\.description | string | 
action\_result\.data\.\*\.status\_availabilityState\.description | string | 
action\_result\.data\.\*\.status\_enabledState\.description | string | 
action\_result\.data\.\*\.status\_statusReason\.description | string | 
action\_result\.data\.\*\.tmName\.description | string | 
action\_result\.data\.\*\.totRequests\.value | numeric | 
action\_result\.summary\.num\_connections | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list nodes'
Fetch a list of nodes \(if no value is provided, all nodes will be returned\)

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**max\_results** |  optional  | Max number of nodes to return | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.max\_results | numeric | 
action\_result\.data\.\*\.address | string |  `ip` 
action\_result\.data\.\*\.connectionLimit | numeric | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.dynamicRatio | numeric | 
action\_result\.data\.\*\.ephemeral | string | 
action\_result\.data\.\*\.fqdn\.addressFamily | string | 
action\_result\.data\.\*\.fqdn\.autopopulate | string | 
action\_result\.data\.\*\.fqdn\.downInterval | numeric | 
action\_result\.data\.\*\.fqdn\.interval | string | 
action\_result\.data\.\*\.fullPath | string | 
action\_result\.data\.\*\.generation | numeric | 
action\_result\.data\.\*\.kind | string | 
action\_result\.data\.\*\.logging | string | 
action\_result\.data\.\*\.monitor | string | 
action\_result\.data\.\*\.name | string |  `f5 node name` 
action\_result\.data\.\*\.partition | string |  `f5 partition name` 
action\_result\.data\.\*\.rateLimit | string | 
action\_result\.data\.\*\.ratio | numeric | 
action\_result\.data\.\*\.selfLink | string |  `url` 
action\_result\.data\.\*\.session | string | 
action\_result\.data\.\*\.state | string | 
action\_result\.summary\.node\_names | string | 
action\_result\.summary\.num\_nodes | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list pools'
Fetch a list of configured pools \(if no value is provided, all pools will be returned\)

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**max\_results** |  optional  | Max number of pools to return | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.max\_results | numeric | 
action\_result\.data\.\*\.allowNat | string | 
action\_result\.data\.\*\.allowSnat | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.fullPath | string | 
action\_result\.data\.\*\.generation | numeric | 
action\_result\.data\.\*\.ignorePersistedWeight | string | 
action\_result\.data\.\*\.ipTosToClient | string | 
action\_result\.data\.\*\.ipTosToServer | string | 
action\_result\.data\.\*\.items\.\*\.addressStatus | string | 
action\_result\.data\.\*\.items\.\*\.autoLasthop | string | 
action\_result\.data\.\*\.items\.\*\.cmpEnabled | string | 
action\_result\.data\.\*\.items\.\*\.connectionLimit | numeric | 
action\_result\.data\.\*\.items\.\*\.creationTime | string | 
action\_result\.data\.\*\.items\.\*\.destination | string | 
action\_result\.data\.\*\.items\.\*\.enabled | boolean | 
action\_result\.data\.\*\.items\.\*\.evictionProtected | string | 
action\_result\.data\.\*\.items\.\*\.fullPath | string | 
action\_result\.data\.\*\.items\.\*\.generation | numeric | 
action\_result\.data\.\*\.items\.\*\.gtmScore | numeric | 
action\_result\.data\.\*\.items\.\*\.ipProtocol | string | 
action\_result\.data\.\*\.items\.\*\.kind | string | 
action\_result\.data\.\*\.items\.\*\.lastModifiedTime | string | 
action\_result\.data\.\*\.items\.\*\.mask | string |  `ip` 
action\_result\.data\.\*\.items\.\*\.mirror | string | 
action\_result\.data\.\*\.items\.\*\.mobileAppTunnel | string | 
action\_result\.data\.\*\.items\.\*\.name | string | 
action\_result\.data\.\*\.items\.\*\.nat64 | string | 
action\_result\.data\.\*\.items\.\*\.partition | string |  `f5 partition name` 
action\_result\.data\.\*\.items\.\*\.policiesReference\.isSubcollection | boolean | 
action\_result\.data\.\*\.items\.\*\.policiesReference\.link | string |  `url` 
action\_result\.data\.\*\.items\.\*\.pool | string | 
action\_result\.data\.\*\.items\.\*\.poolReference\.link | string |  `url` 
action\_result\.data\.\*\.items\.\*\.profilesReference\.isSubcollection | boolean | 
action\_result\.data\.\*\.items\.\*\.profilesReference\.link | string |  `url` 
action\_result\.data\.\*\.items\.\*\.rateLimit | string | 
action\_result\.data\.\*\.items\.\*\.rateLimitDstMask | numeric | 
action\_result\.data\.\*\.items\.\*\.rateLimitMode | string | 
action\_result\.data\.\*\.items\.\*\.rateLimitSrcMask | numeric | 
action\_result\.data\.\*\.items\.\*\.selfLink | string |  `url` 
action\_result\.data\.\*\.items\.\*\.serviceDownImmediateAction | string | 
action\_result\.data\.\*\.items\.\*\.source | string | 
action\_result\.data\.\*\.items\.\*\.sourceAddressTranslation\.type | string | 
action\_result\.data\.\*\.items\.\*\.sourcePort | string | 
action\_result\.data\.\*\.items\.\*\.synCookieStatus | string | 
action\_result\.data\.\*\.items\.\*\.translateAddress | string | 
action\_result\.data\.\*\.items\.\*\.translatePort | string | 
action\_result\.data\.\*\.items\.\*\.vlansDisabled | boolean | 
action\_result\.data\.\*\.items\.\*\.vsIndex | numeric | 
action\_result\.data\.\*\.kind | string | 
action\_result\.data\.\*\.linkQosToClient | string | 
action\_result\.data\.\*\.linkQosToServer | string | 
action\_result\.data\.\*\.loadBalancingMode | string | 
action\_result\.data\.\*\.membersReference\.isSubcollection | boolean | 
action\_result\.data\.\*\.membersReference\.link | string |  `url` 
action\_result\.data\.\*\.minActiveMembers | numeric | 
action\_result\.data\.\*\.minUpMembers | numeric | 
action\_result\.data\.\*\.minUpMembersAction | string | 
action\_result\.data\.\*\.minUpMembersChecking | string | 
action\_result\.data\.\*\.monitor | string | 
action\_result\.data\.\*\.name | string |  `f5 pool name` 
action\_result\.data\.\*\.partition | string |  `f5 partition name` 
action\_result\.data\.\*\.queueDepthLimit | numeric | 
action\_result\.data\.\*\.queueOnConnectionLimit | string | 
action\_result\.data\.\*\.queueTimeLimit | numeric | 
action\_result\.data\.\*\.reselectTries | numeric | 
action\_result\.data\.\*\.selfLink | string |  `url` 
action\_result\.data\.\*\.serviceDownAction | string | 
action\_result\.data\.\*\.slowRampTime | numeric | 
action\_result\.summary\.num\_pools | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list members'
Fetch a list of configured node members of a pool \(if no value is provided, all node members of a pool will be returned\)

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**pool\_name** |  required  | Name of the pool | string |  `f5 pool name` 
**partition\_name** |  required  | Name of the partition | string |  `f5 partition name` 
**max\_results** |  optional  | Max number of members to return | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.max\_results | numeric | 
action\_result\.parameter\.partition\_name | string |  `f5 partition name` 
action\_result\.parameter\.pool\_name | string |  `f5 pool name` 
action\_result\.data\.\*\.address | string |  `ip` 
action\_result\.data\.\*\.connectionLimit | numeric | 
action\_result\.data\.\*\.dynamicRatio | numeric | 
action\_result\.data\.\*\.ephemeral | string | 
action\_result\.data\.\*\.fqdn\.autopopulate | string | 
action\_result\.data\.\*\.fullPath | string | 
action\_result\.data\.\*\.generation | numeric | 
action\_result\.data\.\*\.inheritProfile | string | 
action\_result\.data\.\*\.kind | string | 
action\_result\.data\.\*\.logging | string | 
action\_result\.data\.\*\.monitor | string | 
action\_result\.data\.\*\.name | string |  `f5 node name` 
action\_result\.data\.\*\.partition | string |  `f5 partition name` 
action\_result\.data\.\*\.priorityGroup | numeric | 
action\_result\.data\.\*\.rateLimit | string | 
action\_result\.data\.\*\.ratio | numeric | 
action\_result\.data\.\*\.selfLink | string |  `url` 
action\_result\.data\.\*\.session | string | 
action\_result\.data\.\*\.state | string | 
action\_result\.summary\.members | string | 
action\_result\.summary\.num\_members | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 