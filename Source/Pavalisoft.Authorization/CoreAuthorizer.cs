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

using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.AspNetCore.Mvc.Filters;
using Pavalisoft.Authorization.Interfaces;

namespace Pavalisoft.Authorization
{
    public class CoreAuthorizer : IAuthorizer
    {
        public async Task OnAuthorizationAsync(AuthorizationPolicy effectivePolicy, AuthorizationFilterContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (effectivePolicy == null)
            {
                throw new ArgumentNullException(nameof(effectivePolicy));
            }

            await new AuthorizeFilter(effectivePolicy).OnAuthorizationAsync(context);
        }
    }
}
