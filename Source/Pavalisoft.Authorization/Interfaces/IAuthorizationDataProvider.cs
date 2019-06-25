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
using Microsoft.AspNetCore.Mvc.Controllers;

namespace Pavalisoft.Authorization.Interfaces
{
    public interface IAuthorizationDataProvider
    {
        /// <summary>
        /// Provides Authorization Settings
        /// </summary>
        /// <returns></returns>
        AuthorizationSettings GetAuthorizationSettings();

        /// <summary>
        /// Provides the Authorization Policies to be configured for application
        /// </summary>
        /// <returns></returns>
        IEnumerable<AuthorizationPolicyInfo> GetAuthorizationPolicies();

        /// <summary>
        /// Provides the Area, Controller and Actionwise Authorization Data
        /// </summary>
        /// <param name="descriptor"></param>
        /// <returns></returns>
        IEnumerable<IAuthorizeData> GetAuthorizeData(ControllerActionDescriptor descriptor);
    }
}
