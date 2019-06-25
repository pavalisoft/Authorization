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

using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;

namespace Pavalisoft.Authorization
{
    /// <summary>
    /// Implements an <see cref="T:Microsoft.AspNetCore.Authorization.IAuthorizationHandler" /> and <see cref="T:Microsoft.AspNetCore.Authorization.IAuthorizationRequirement" />
    /// which requires at least one role claim whose value must be any of the allowed roles.
    /// </summary>
    public class DenyAuthorizationRequirement : AuthorizationHandler<DenyAuthorizationRequirement>, IAuthorizationRequirement
    {
        /// <summary>
        /// Makes a decision if authorization is allowed based on a specific requirement.
        /// </summary>
        /// <param name="context">The authorization context.</param>
        /// <param name="requirement">The requirement to evaluate.</param>
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
            DenyAuthorizationRequirement requirement)
        {
            return Task.CompletedTask;
        }
    }
}
