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
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Server.IISIntegration;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json.Linq;
using Pavalisoft.Authorization.Interfaces;

namespace Pavalisoft.Authorization
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddCoreAuthorization<TFilterType>(this IServiceCollection services,
            IConfiguration configuration) where TFilterType : IFilterMetadata
        {
            AddFilter<TFilterType>(services, configuration);
            AddPolicies(services);
            return services;
        }

        private static void AddPolicies(IServiceCollection services)
        {
            IServiceProvider serviceProvider = new DefaultServiceProviderFactory().CreateServiceProvider(services);
            if (serviceProvider == null)
                throw new ArgumentNullException(nameof(serviceProvider));

            var authorizationDataProvider = serviceProvider.GetService<IAuthorizationDataProvider>();

            var policies = authorizationDataProvider?.GetAuthorizationPolicies();
            if (policies == null) return;

            var authorizationPolicies = policies as IList<AuthorizationPolicyInfo> ?? policies.ToList();
            if (authorizationPolicies.Any())
            {
                services.AddAuthorization(config =>
                {
                    foreach (var policy in authorizationPolicies)
                    {
                        BuildPolicy(policy, config);
                    }
                });

            }
        }

        private static void AddFilter<TFilterType>(IServiceCollection services, IConfiguration configuration)
            where TFilterType : IFilterMetadata
        {
            if (services == null)
                throw new ArgumentNullException(nameof(services));
            if (configuration == null)
                throw new ArgumentNullException(nameof(configuration));
            services.AddAuthenticationCore(options =>
            {
                options.DefaultForbidScheme = IISDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = IISDefaults.AuthenticationScheme;
            });
            services.AddSingleton<IAuthorizationDataProvider, ConfigurationAuthorizationDataProvider>();
            services.AddTransient<IAuthorizer, CoreAuthorizer>();
            services.AddMvc(options => { options.Filters.Add<TFilterType>(); });
        }

        private static void BuildPolicy(AuthorizationPolicyInfo policy, AuthorizationOptions config)
        {
            var builder = new AuthorizationPolicyBuilder();
            policy.AuthenticationSchemes?.ForEach(builder.AuthenticationSchemes.Add);
            if (policy.Requirements != null && policy.Requirements.Any())
            {
                foreach (var policyRequirement in policy.Requirements)
                {
                    switch (policyRequirement.RequirementType)
                    {
                        case AuthorizationRequirementType.ClaimsAuthorizationRequirement:
                            var claimsInfo = JObject.Parse(policyRequirement.Requirement)
                                .ToObject<ClaimsInfo>();
                            builder.RequireClaim(claimsInfo.ClaimType, claimsInfo.RequiredValues);
                            break;
                        case AuthorizationRequirementType.RolesAuthorizationRequirement:
                            builder.RequireRole(JObject.Parse(policyRequirement.Requirement)
                                .ToObject<string[]>());
                            break;
                        case AuthorizationRequirementType.NameAuthorizationRequirement:
                            builder.RequireUserName(policyRequirement.Requirement);
                            break;
                        case AuthorizationRequirementType.OperationAuthorizationRequirement:
                            builder.AddRequirements(
                                new OperationAuthorizationRequirement()
                                {
                                    Name = policyRequirement.Requirement
                                });
                            break;
                        case AuthorizationRequirementType.DenyAnonymousAuthorizationRequirement:
                            builder.RequireAuthenticatedUser();
                            break;
                        case AuthorizationRequirementType.DenyAuthorizationRequirement:
                            builder.AddRequirements(new DenyAuthorizationRequirement());
                            break;
                        case AuthorizationRequirementType.CustomAuthorizationRequirement:
                            builder.AddRequirements(Activator.CreateInstance(Type.GetType(policyRequirement.Type),
                                JObject.Parse(policyRequirement.Requirement).ToObject<object[]>()) as IAuthorizationRequirement);
                            break;
                            // TODO implement the assertion requirement.
                            //case AuthorizationRequirementType.ClaimsAuthorizationRequirement:
                            //    builder.RequireAssertion(handler => {handler.})
                            //    break;
                    }
                }
            }
            config.AddPolicy(policy.Name, builder.Build());
        }
    }

    public class ClaimsInfo
    {
        public string ClaimType { get; set; }
        public string[] RequiredValues { get; set; }
    }
}
