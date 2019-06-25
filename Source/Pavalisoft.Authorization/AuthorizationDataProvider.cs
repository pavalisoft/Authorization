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
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Pavalisoft.Authorization.Interfaces;

namespace Pavalisoft.Authorization
{
    public abstract class AuthorizationDataProvider : IAuthorizationDataProvider
    {
        private AuthorizationSettings _authorizationSettings;

        private AuthorizationSettings AuthorizationSettings => _authorizationSettings ?? (_authorizationSettings = LoadAuthorizationSettings());

        public abstract AuthorizationSettings LoadAuthorizationSettings();

        public AuthorizationSettings GetAuthorizationSettings()
        {
            return AuthorizationSettings;
        }

        public IEnumerable<AuthorizationPolicyInfo> GetAuthorizationPolicies()
        {
            return AuthorizationSettings.Policies;
        }

        public IEnumerable<IAuthorizeData> GetAuthorizeData(ControllerActionDescriptor descriptor)
        {
            return GetAuthorizeFilters(descriptor);
        }

        private IEnumerable<IAuthorizeData> GetAuthorizeData(AuthorizationAction authorizationAction)
        {
            if (string.IsNullOrWhiteSpace(authorizationAction.Roles) &&
                string.IsNullOrWhiteSpace(authorizationAction.Policy))
                return null;
            return new[]
            {
                authorizationAction
            };
        }

        private string GetAreaName(ControllerActionDescriptor controllerActionDescriptor)
        {
            if (controllerActionDescriptor.ControllerTypeInfo.GetCustomAttributes(typeof(AreaAttribute), false)
                .FirstOrDefault() is AreaAttribute areaAttribute)
                return areaAttribute.RouteValue;
            return "Default";
        }

        private IEnumerable<IAuthorizeData> GetAuthorizeFilters(ControllerActionDescriptor controllerActionDescriptor)
        {
            if (controllerActionDescriptor == null)
                throw new ArgumentNullException(nameof(controllerActionDescriptor));
            if (AuthorizationSettings == null)
                throw new ArgumentNullException(nameof(Authorization.AuthorizationSettings));

            string areaName = GetAreaName(controllerActionDescriptor);
            string actionName = controllerActionDescriptor.ActionName;
            string controllerName = controllerActionDescriptor.ControllerName;
            AuthorizationArea authorizationArea =
                AuthorizationSettings.Areas.FirstOrDefault(area => area.Name == areaName);
            if (authorizationArea == null)
                return null;
            AuthorizationController authorizationController =
                authorizationArea.Controllers.FirstOrDefault(controller => controller.Name == controllerName);
            if (authorizationController == null)
                return GetAuthorizeData(authorizationArea);
            AuthorizationAction authorizationAction =
                authorizationController.Actions.FirstOrDefault(action => action.Name == actionName);
            if (authorizationAction == null)
                return GetAuthorizeData(authorizationController);
            return GetAuthorizeData(authorizationAction);
        }
    }
}
