/* 
   Copyright 2019 Pavalisoft

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License. 
*/

using System.Collections.Generic;
using Microsoft.AspNetCore.Authorization;

namespace Pavalisoft.Authorization
{
    /// <summary>
    /// {
    ///     "Authorization" : {
    ///         "Policies" : [],
    ///         "Areas" : [
    ///             {
    ///                 "Name" : "Default",
    ///                 "Roles" : "",
    ///                 "Policy" : "",
    ///                 "Controllers" : [
    ///                     {
    ///                         "Name" : "Home",
    ///                         "Roles" : "",
    ///                         "Policy" : "",
    ///                         "Actions" : [
    ///                             {
    ///                                 "Name" : "Index",
    ///                                 "Roles" : "",
    ///                                 "Policy" : ""
    ///                             },
    ///                             {
    ///                                 "Name" : "About",
    ///                                 "Roles" : "",
    ///                                 "Policy" : ""
    ///                             },
    ///                             {
    ///                                 "Name" : "Contact",
    ///                                 "Roles" : "",
    ///                                 "Policy" : ""
    ///                             },
    ///                             {
    ///                                 "Name" : "Error",
    ///                                 "Roles" : "",
    ///                                 "Policy" : ""
    ///                             }
    ///                         ]
    ///                     }
    ///                 ]
    ///             }
    ///         ]
    ///     }
    /// }
    /// </summary>
    public class AuthorizationSettings
    {
        public List<AuthorizationPolicyInfo> Policies { get; set; }
        public List<AuthorizationArea> Areas { get; set; }
    }

    public class AuthorizationArea : AuthorizationAction
    {
        public List<AuthorizationController> Controllers { get; set; }
    }

    public class AuthorizationController : AuthorizationAction
    {
        public List<AuthorizationAction> Actions { get; set; }
    }

    public class AuthorizationAction : IAuthorizeData
    {
        public string Name { get; set; }
        public string Policy { get; set; }
        public string Roles { get; set; }
        public string AuthenticationSchemes { get; set; }
    }

    public class AuthorizationPolicyInfo
    {
        public string Name { get; set; }
        public List<AuthorizationRequirement> Requirements { get; set; }
        public List<string> AuthenticationSchemes { get; set; }
    }

    public class AuthorizationRequirement
    {
        public AuthorizationRequirementType RequirementType { get; set; }
        public string Type { get; set; }
        public string Requirement { get; set; }
    }

    public enum AuthorizationRequirementType
    {
        AssertionRequirement,
        ClaimsAuthorizationRequirement,
        DenyAnonymousAuthorizationRequirement,
        NameAuthorizationRequirement,
        OperationAuthorizationRequirement,
        RolesAuthorizationRequirement,
        DenyAuthorizationRequirement,
        CustomAuthorizationRequirement
    }
}