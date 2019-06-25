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
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.Controllers;
using Pavalisoft.Authorization.Interfaces;

namespace Pavalisoft.Authorization
{
    public class CoreAuthorizeFilter : IAsyncAuthorizationFilter, IFilterFactory
    {
        private readonly IAuthorizationDataProvider _authorizationDataProvider;
        private readonly IAuthorizationPolicyProvider _authorizationPolicyProvider;

        public CoreAuthorizeFilter(IAuthorizationDataProvider authorizationDataProvider, IAuthorizer authorizer,
            IAuthorizationPolicyProvider policyProvider)
        {
            _authorizationDataProvider = authorizationDataProvider;
            BaseAuthorizor = authorizer;
            _authorizationPolicyProvider = policyProvider;
            BaseAuthorizationPolicy = ConstructBaseAuthorizationPolicy();
        }

        public virtual async Task OnAuthorizationAsync(AuthorizationFilterContext context)
        {
            if (BaseAuthorizationPolicy == null)
                throw new ArgumentNullException(nameof(BaseAuthorizationPolicy));
            var effectivePolicy = ConstructAuthorizationPolicy(context.ActionDescriptor as ControllerActionDescriptor);

            if (effectivePolicy == null)
            {
                return;
            }
            await BaseAuthorizor.OnAuthorizationAsync(effectivePolicy, context);
        }

        public AuthorizationPolicy ConstructAuthorizationPolicy(ControllerActionDescriptor context)
        {
            if (_authorizationDataProvider == null)
                throw new ArgumentNullException(nameof(_authorizationDataProvider));

            if (context == null)
                throw new ArgumentNullException(nameof(context));

            if (_authorizationPolicyProvider == null)
                throw new ArgumentNullException(nameof(_authorizationPolicyProvider));

            var authorizeData = _authorizationDataProvider.GetAuthorizeData(context);

            AuthorizationPolicy newPolicy;

            if (authorizeData == null)
            {
                var builder = new AuthorizationPolicyBuilder();
                newPolicy = builder.AddRequirements(new DenyAuthorizationRequirement()).Build();
            }
            else
            {
                newPolicy = AuthorizationPolicy
                    .CombineAsync(_authorizationPolicyProvider, authorizeData).Result;
            }

            return AuthorizationPolicy.Combine(BaseAuthorizationPolicy, newPolicy);
        }

        private AuthorizationPolicy ConstructBaseAuthorizationPolicy()
        {
            return new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .Build();
        }

        public IFilterMetadata CreateInstance(IServiceProvider serviceProvider)
        {
            return this;
        }

        bool IFilterFactory.IsReusable => true;

        public AuthorizationPolicy BaseAuthorizationPolicy { get; }

        public IAuthorizer BaseAuthorizor { get; }
    }
}
