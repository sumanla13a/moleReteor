meteor-roles
============

This is a fork of alanning:meteor roles

It creates a groups collection

structure of groups collection
{
  "name": "String", //name of group
  "roles": ["String"] //roles is array of string
}

added functions:

Roles.getAllGroups() //gets all groups 
Roles.getAllRolesInGroup() //gets all roles inside a group
Roles.addRoleToGroup() //Checks if role exists in roles table, if yes adds it to the group


Addition
On adding a user,
if group name is passed,
    it searches if the group exists
        if yes, 
          it checks 
            if all the roles is available on the group collection
            if no adds the roles
        if group doesnot exist
          it adds the group to groups collection



//Feel free to suggest updates or report bug at
lamasuman2@gmail.com
