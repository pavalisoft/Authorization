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
using Microsoft.AspNetCore.Mvc.Filters;

namespace Pavalisoft.Authorization.Interfaces
{
    public interface IAuthorizer
    {
        /// <summary>
        /// Authoirizes the <see cref="Microsoft.AspNetCore.Mvc.Controllers.ControllerActionDescriptor"/> against the <see cref="AuthorizationPolicy"/>
        /// </summary>
        /// <returns></returns>
        Task OnAuthorizationAsync(AuthorizationPolicy effectivePolicy, AuthorizationFilterContext context);
    }
}
