// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace AspNetCore.Authentication.ApiKey.Tests
{
    public class ApiKeyExtensionsTests
    {
        #region API Key - In Header

        #region Verify Auth Scheme

        [Fact]
        public async Task AddApiKeyInHeader_verify_auth_scheme_handler_default()
        {
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInHeader());
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInHeaderHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
        }

        [Fact]
        public async Task AddApiKeyInHeader_verify_auth_scheme_handler_with_scheme()
        {
            var schemeName = "CustomScheme";
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInHeader(schemeName), schemeName);
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInHeaderHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        [Fact]
        public async Task AddApiKeyInHeader_verify_auth_scheme_handler_with_configureOptions()
        {
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInHeader(_ => { }));
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInHeaderHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
        }

        [Fact]
        public async Task AddApiKeyInHeader_verify_auth_scheme_handler_with_scheme_and_configureOptions()
        {
            var schemeName = "CustomScheme";
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInHeader(schemeName, _ => { }), schemeName);
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInHeaderHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        [Fact]
        public async Task AddApiKeyInHeader_verify_auth_scheme_handler_with_scheme_displayName_and_configureOptions()
        {
            var schemeName = "CustomScheme";
            var displayName = "DisplayName";
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInHeader(schemeName, displayName, _ => { }), schemeName);
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInHeaderHandler), scheme.HandlerType.Name);
            Assert.NotNull(scheme.DisplayName);
            Assert.Equal(displayName, scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }


        [Fact]
        public async Task AddApiKeyInHeader_TApiKeyProvider_verify_auth_scheme_handler_default()
        {
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInHeader<MockApiKeyAuthenticationService>(), ApiKeyDefaults.AuthenticationScheme);
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInHeaderHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
        }

        [Fact]
        public async Task AddApiKeyInHeader_TApiKeyProvider_verify_auth_scheme_handler_with_scheme()
        {
            var schemeName = "CustomScheme";
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInHeader<MockApiKeyAuthenticationService>(schemeName), schemeName);
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInHeaderHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        [Fact]
        public async Task AddApiKeyInHeader_TApiKeyProvider_verify_auth_scheme_handler_with_configureOptions()
        {
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInHeader<MockApiKeyAuthenticationService>(_ => { }));
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInHeaderHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
        }

        [Fact]
        public async Task AddApiKeyInHeader_TApiKeyProvider_verify_auth_scheme_handler_with_scheme_and_configureOptions()
        {
            var schemeName = "CustomScheme";
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInHeader<MockApiKeyAuthenticationService>(schemeName, _ => { }), schemeName);
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInHeaderHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        [Fact]
        public async Task AddApiKeyInHeader_TApiKeyProvider_verify_auth_scheme_handler_with_scheme_displayName_and_configureOptions()
        {
            var schemeName = "CustomScheme";
            var displayName = "DisplayName";
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInHeader<MockApiKeyAuthenticationService>(schemeName, displayName, _ => { }), schemeName);
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInHeaderHandler), scheme.HandlerType.Name);
            Assert.NotNull(scheme.DisplayName);
            Assert.Equal(displayName, scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        #endregion  // Verify Auth Scheme

        #region Allows Multiple Schemes

        [Fact]
        public async Task AddApiKeyInHeader_allows_multiple_schemes()
        {
            var schemeName = "CustomScheme";
            var displayName = "DisplayName";

            var services = new ServiceCollection();
            services.AddAuthentication()
                .AddApiKeyInHeader()
                .AddApiKeyInHeader(schemeName, displayName, _ => { });

            var sp = services.BuildServiceProvider();
            var schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
            var defaultScheme = await schemeProvider.GetSchemeAsync(ApiKeyDefaults.AuthenticationScheme);
            var scheme = await schemeProvider.GetSchemeAsync(schemeName);

            Assert.NotNull(defaultScheme);
            Assert.Equal(nameof(ApiKeyInHeaderHandler), defaultScheme.HandlerType.Name);
            Assert.Null(defaultScheme.DisplayName);
            Assert.Equal(ApiKeyDefaults.AuthenticationScheme, defaultScheme.Name);

            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInHeaderHandler), scheme.HandlerType.Name);
            Assert.NotNull(scheme.DisplayName);
            Assert.Equal(displayName, scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        [Fact]
        public async Task AddApiKeyInHeader_TApiKeyProvider_allows_multiple_schemes()
        {
            var schemeName = "CustomScheme";
            var displayName = "DisplayName";

            var services = new ServiceCollection();
            services.AddAuthentication()
                .AddApiKeyInHeader<MockApiKeyAuthenticationService>()
                .AddApiKeyInHeader<MockApiKeyAuthenticationService>(schemeName, displayName, _ => { });

            var sp = services.BuildServiceProvider();
            var schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
            var defaultScheme = await schemeProvider.GetSchemeAsync(ApiKeyDefaults.AuthenticationScheme);
            var scheme = await schemeProvider.GetSchemeAsync(schemeName);

            Assert.NotNull(defaultScheme);
            Assert.Equal(nameof(ApiKeyInHeaderHandler), defaultScheme.HandlerType.Name);
            Assert.Null(defaultScheme.DisplayName);
            Assert.Equal(ApiKeyDefaults.AuthenticationScheme, defaultScheme.Name);

            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInHeaderHandler), scheme.HandlerType.Name);
            Assert.NotNull(scheme.DisplayName);
            Assert.Equal(displayName, scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        #endregion  // Allows Multiple Schemes

        #region TApiKeyProvider tests

        [Fact]
        public void AddApiKeyInHeader_TApiKeyProvider_IApiKeyProvider_is_registered_as_transient()
        {
            var services = new ServiceCollection();
            services.AddAuthentication()
                .AddApiKeyInHeader<MockApiKeyAuthenticationService>();

            var serviceDescriptor = Assert.Single(services.Where(s => s.ServiceType == typeof(IApiKeyAuthenticationService)));
            Assert.Equal(typeof(IApiKeyAuthenticationService), serviceDescriptor.ServiceType);
            Assert.Equal(typeof(MockApiKeyAuthenticationService), serviceDescriptor.ImplementationType);
            Assert.Equal(ServiceLifetime.Transient, serviceDescriptor.Lifetime);

            var sp = services.BuildServiceProvider();
            var provider = sp.GetService<IApiKeyAuthenticationService>();

            Assert.NotNull(provider);
            Assert.Equal(typeof(MockApiKeyAuthenticationService), provider.GetType());
        }

        [Fact]
        public void AddApiKeyInHeader_TApiKeyProvider_does_not_replace_previously_user_registered_IApiKeyProvider()
        {
            var services = new ServiceCollection();
            services.AddSingleton<IApiKeyAuthenticationService, MockApiKeyProvider2>();
            services.AddAuthentication()
                .AddApiKeyInHeader<MockApiKeyAuthenticationService>();

            var serviceDescriptors = services.Where(s => s.ServiceType == typeof(IApiKeyAuthenticationService));
            Assert.Equal(2, serviceDescriptors.Count());

            var serviceDescriptor = Assert.Single(serviceDescriptors.Where(s => s.ImplementationType == typeof(MockApiKeyAuthenticationService)));
            Assert.Equal(typeof(IApiKeyAuthenticationService), serviceDescriptor.ServiceType);
            Assert.Equal(typeof(MockApiKeyAuthenticationService), serviceDescriptor.ImplementationType);
            Assert.Equal(ServiceLifetime.Transient, serviceDescriptor.Lifetime);

            serviceDescriptor = Assert.Single(serviceDescriptors.Where(s => s.ImplementationType == typeof(MockApiKeyProvider2)));
            Assert.Equal(typeof(IApiKeyAuthenticationService), serviceDescriptor.ServiceType);
            Assert.Equal(typeof(MockApiKeyProvider2), serviceDescriptor.ImplementationType);
            Assert.Equal(ServiceLifetime.Singleton, serviceDescriptor.Lifetime);
        }

        #endregion  // TApiKeyProvider tests

        #region Allows chaining

        [Fact]
        public void AddApiKeyInHeader_allows_chaining_default()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeader());
        }

        [Fact]
        public void AddApiKeyInHeader_allows_chaining_with_scheme()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeader(string.Empty));
        }

        [Fact]
        public void AddApiKeyInHeader_allows_chaining_with_configureOptions()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeader(_ => { }));
        }

        [Fact]
        public void AddApiKeyInHeader_allows_chaining_with_scheme_and_configureOptions()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeader(string.Empty, _ => { }));
        }

        [Fact]
        public void AddApiKeyInHeader_allows_chaining_with_scheme_displayName_and_configureOptions()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeader(string.Empty, string.Empty, _ => { }));
        }


        [Fact]
        public void AddApiKeyInHeader_TApiKeyProvider_allows_chaining()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeader<MockApiKeyAuthenticationService>());
        }

        [Fact]
        public void AddApiKeyInHeader_TApiKeyProvider_allows_chaining_with_scheme()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeader<MockApiKeyAuthenticationService>(string.Empty));
        }

        [Fact]
        public void AddApiKeyInHeader_TApiKeyProvider_allows_chaining_with_configureOptions()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeader<MockApiKeyAuthenticationService>(_ => { }));
        }

        [Fact]
        public void AddApiKeyInHeader_TApiKeyProvider_allows_chaining_with_scheme_and_configureOptions()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeader<MockApiKeyAuthenticationService>(string.Empty, _ => { }));
        }

        [Fact]
        public void AddApiKeyInHeader_TApiKeyProvider_allows_chaining_with_scheme_displayName_and_configureOptions()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeader<MockApiKeyAuthenticationService>(string.Empty, string.Empty, _ => { }));
        }

        #endregion // Allows chaining

        #endregion // API Key - In Header

        #region API Key - In Authorization Header

        #region Verify Auth Scheme

        [Fact]
        public async Task AddApiKeyInAuthorizationHeader_verify_auth_scheme_handler_default()
        {
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInAuthorizationHeader());
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInAuthorizationHeaderHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
        }

        [Fact]
        public async Task AddApiKeyInAuthorizationHeader_verify_auth_scheme_handler_with_scheme()
        {
            var schemeName = "CustomScheme";
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInAuthorizationHeader(schemeName), schemeName);
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInAuthorizationHeaderHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        [Fact]
        public async Task AddApiKeyInAuthorizationHeader_verify_auth_scheme_handler_with_configureOptions()
        {
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInAuthorizationHeader(_ => { }));
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInAuthorizationHeaderHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
        }

        [Fact]
        public async Task AddApiKeyInAuthorizationHeader_verify_auth_scheme_handler_with_scheme_and_configureOptions()
        {
            var schemeName = "CustomScheme";
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInAuthorizationHeader(schemeName, _ => { }), schemeName);
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInAuthorizationHeaderHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        [Fact]
        public async Task AddApiKeyInAuthorizationHeader_verify_auth_scheme_handler_with_scheme_displayName_and_configureOptions()
        {
            var schemeName = "CustomScheme";
            var displayName = "DisplayName";
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInAuthorizationHeader(schemeName, displayName, _ => { }), schemeName);
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInAuthorizationHeaderHandler), scheme.HandlerType.Name);
            Assert.NotNull(scheme.DisplayName);
            Assert.Equal(displayName, scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }


        [Fact]
        public async Task AddApiKeyInAuthorizationHeader_TApiKeyProvider_verify_auth_scheme_handler_default()
        {
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInAuthorizationHeader<MockApiKeyAuthenticationService>(), ApiKeyDefaults.AuthenticationScheme);
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInAuthorizationHeaderHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
        }

        [Fact]
        public async Task AddApiKeyInAuthorizationHeader_TApiKeyProvider_verify_auth_scheme_handler_with_scheme()
        {
            var schemeName = "CustomScheme";
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInAuthorizationHeader<MockApiKeyAuthenticationService>(schemeName), schemeName);
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInAuthorizationHeaderHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        [Fact]
        public async Task AddApiKeyInAuthorizationHeader_TApiKeyProvider_verify_auth_scheme_handler_with_configureOptions()
        {
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInAuthorizationHeader<MockApiKeyAuthenticationService>(_ => { }));
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInAuthorizationHeaderHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
        }

        [Fact]
        public async Task AddApiKeyInAuthorizationHeader_TApiKeyProvider_verify_auth_scheme_handler_with_scheme_and_configureOptions()
        {
            var schemeName = "CustomScheme";
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInAuthorizationHeader<MockApiKeyAuthenticationService>(schemeName, _ => { }), schemeName);
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInAuthorizationHeaderHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        [Fact]
        public async Task AddApiKeyInAuthorizationHeader_TApiKeyProvider_verify_auth_scheme_handler_with_scheme_displayName_and_configureOptions()
        {
            var schemeName = "CustomScheme";
            var displayName = "DisplayName";
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInAuthorizationHeader<MockApiKeyAuthenticationService>(schemeName, displayName, _ => { }), schemeName);
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInAuthorizationHeaderHandler), scheme.HandlerType.Name);
            Assert.NotNull(scheme.DisplayName);
            Assert.Equal(displayName, scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        #endregion  // Verify Auth Scheme

        #region Allows Multiple Schemes

        [Fact]
        public async Task AddApiKeyInAuthorizationHeader_allows_multiple_schemes()
        {
            var schemeName = "CustomScheme";
            var displayName = "DisplayName";

            var services = new ServiceCollection();
            services.AddAuthentication()
                .AddApiKeyInAuthorizationHeader()
                .AddApiKeyInAuthorizationHeader(schemeName, displayName, _ => { });

            var sp = services.BuildServiceProvider();
            var schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
            var defaultScheme = await schemeProvider.GetSchemeAsync(ApiKeyDefaults.AuthenticationScheme);
            var scheme = await schemeProvider.GetSchemeAsync(schemeName);

            Assert.NotNull(defaultScheme);
            Assert.Equal(nameof(ApiKeyInAuthorizationHeaderHandler), defaultScheme.HandlerType.Name);
            Assert.Null(defaultScheme.DisplayName);
            Assert.Equal(ApiKeyDefaults.AuthenticationScheme, defaultScheme.Name);

            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInAuthorizationHeaderHandler), scheme.HandlerType.Name);
            Assert.NotNull(scheme.DisplayName);
            Assert.Equal(displayName, scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        [Fact]
        public async Task AddApiKeyInAuthorizationHeader_TApiKeyProvider_allows_multiple_schemes()
        {
            var schemeName = "CustomScheme";
            var displayName = "DisplayName";

            var services = new ServiceCollection();
            services.AddAuthentication()
                .AddApiKeyInAuthorizationHeader<MockApiKeyAuthenticationService>()
                .AddApiKeyInAuthorizationHeader<MockApiKeyAuthenticationService>(schemeName, displayName, _ => { });

            var sp = services.BuildServiceProvider();
            var schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
            var defaultScheme = await schemeProvider.GetSchemeAsync(ApiKeyDefaults.AuthenticationScheme);
            var scheme = await schemeProvider.GetSchemeAsync(schemeName);

            Assert.NotNull(defaultScheme);
            Assert.Equal(nameof(ApiKeyInAuthorizationHeaderHandler), defaultScheme.HandlerType.Name);
            Assert.Null(defaultScheme.DisplayName);
            Assert.Equal(ApiKeyDefaults.AuthenticationScheme, defaultScheme.Name);

            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInAuthorizationHeaderHandler), scheme.HandlerType.Name);
            Assert.NotNull(scheme.DisplayName);
            Assert.Equal(displayName, scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        #endregion  // Allows Multiple Schemes

        #region TApiKeyProvider tests

        [Fact]
        public void AddApiKeyInAuthorizationHeader_TApiKeyProvider_IApiKeyProvider_is_registered_as_transient()
        {
            var services = new ServiceCollection();
            services.AddAuthentication()
                .AddApiKeyInAuthorizationHeader<MockApiKeyAuthenticationService>();

            var serviceDescriptor = Assert.Single(services.Where(s => s.ServiceType == typeof(IApiKeyAuthenticationService)));
            Assert.Equal(typeof(IApiKeyAuthenticationService), serviceDescriptor.ServiceType);
            Assert.Equal(typeof(MockApiKeyAuthenticationService), serviceDescriptor.ImplementationType);
            Assert.Equal(ServiceLifetime.Transient, serviceDescriptor.Lifetime);

            var sp = services.BuildServiceProvider();
            var provider = sp.GetService<IApiKeyAuthenticationService>();

            Assert.NotNull(provider);
            Assert.Equal(typeof(MockApiKeyAuthenticationService), provider.GetType());
        }

        [Fact]
        public void AddApiKeyInAuthorizationHeader_TApiKeyProvider_does_not_replace_previously_user_registered_IApiKeyProvider()
        {
            var services = new ServiceCollection();
            services.AddSingleton<IApiKeyAuthenticationService, MockApiKeyProvider2>();
            services.AddAuthentication()
                .AddApiKeyInAuthorizationHeader<MockApiKeyAuthenticationService>();

            var serviceDescriptors = services.Where(s => s.ServiceType == typeof(IApiKeyAuthenticationService));
            Assert.Equal(2, serviceDescriptors.Count());

            var serviceDescriptor = Assert.Single(serviceDescriptors.Where(s => s.ImplementationType == typeof(MockApiKeyAuthenticationService)));
            Assert.Equal(typeof(IApiKeyAuthenticationService), serviceDescriptor.ServiceType);
            Assert.Equal(typeof(MockApiKeyAuthenticationService), serviceDescriptor.ImplementationType);
            Assert.Equal(ServiceLifetime.Transient, serviceDescriptor.Lifetime);

            serviceDescriptor = Assert.Single(serviceDescriptors.Where(s => s.ImplementationType == typeof(MockApiKeyProvider2)));
            Assert.Equal(typeof(IApiKeyAuthenticationService), serviceDescriptor.ServiceType);
            Assert.Equal(typeof(MockApiKeyProvider2), serviceDescriptor.ImplementationType);
            Assert.Equal(ServiceLifetime.Singleton, serviceDescriptor.Lifetime);
        }

        #endregion  // TApiKeyProvider tests

        #region Allows chaining

        [Fact]
        public void AddApiKeyInAuthorizationHeader_allows_chaining_default()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInAuthorizationHeader());
        }

        [Fact]
        public void AddApiKeyInAuthorizationHeader_allows_chaining_with_scheme()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInAuthorizationHeader(string.Empty));
        }

        [Fact]
        public void AddApiKeyInAuthorizationHeader_allows_chaining_with_configureOptions()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInAuthorizationHeader(_ => { }));
        }

        [Fact]
        public void AddApiKeyInAuthorizationHeader_allows_chaining_with_scheme_and_configureOptions()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInAuthorizationHeader(string.Empty, _ => { }));
        }

        [Fact]
        public void AddApiKeyInAuthorizationHeader_allows_chaining_with_scheme_displayName_and_configureOptions()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInAuthorizationHeader(string.Empty, string.Empty, _ => { }));
        }


        [Fact]
        public void AddApiKeyInAuthorizationHeader_TApiKeyProvider_allows_chaining()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInAuthorizationHeader<MockApiKeyAuthenticationService>());
        }

        [Fact]
        public void AddApiKeyInAuthorizationHeader_TApiKeyProvider_allows_chaining_with_scheme()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInAuthorizationHeader<MockApiKeyAuthenticationService>(string.Empty));
        }

        [Fact]
        public void AddApiKeyInAuthorizationHeader_TApiKeyProvider_allows_chaining_with_configureOptions()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInAuthorizationHeader<MockApiKeyAuthenticationService>(_ => { }));
        }

        [Fact]
        public void AddApiKeyInAuthorizationHeader_TApiKeyProvider_allows_chaining_with_scheme_and_configureOptions()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInAuthorizationHeader<MockApiKeyAuthenticationService>(string.Empty, _ => { }));
        }

        [Fact]
        public void AddApiKeyInAuthorizationHeader_TApiKeyProvider_allows_chaining_with_scheme_displayName_and_configureOptions()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInAuthorizationHeader<MockApiKeyAuthenticationService>(string.Empty, string.Empty, _ => { }));
        }

        #endregion // Allows chaining

        #endregion // API Key - In Authorization Header

        #region API Key - In Query Parameters

        #region Verify Auth Scheme

        [Fact]
        public async Task AddApiKeyInQueryParams_verify_auth_scheme_handler_default()
        {
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInQueryParams());
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInQueryParamsHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
        }

        [Fact]
        public async Task AddApiKeyInQueryParams_verify_auth_scheme_handler_with_scheme()
        {
            var schemeName = "CustomScheme";
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInQueryParams(schemeName), schemeName);
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInQueryParamsHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        [Fact]
        public async Task AddApiKeyInQueryParams_verify_auth_scheme_handler_with_configureOptions()
        {
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInQueryParams(_ => { }));
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInQueryParamsHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
        }

        [Fact]
        public async Task AddApiKeyInQueryParams_verify_auth_scheme_handler_with_scheme_and_configureOptions()
        {
            var schemeName = "CustomScheme";
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInQueryParams(schemeName, _ => { }), schemeName);
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInQueryParamsHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        [Fact]
        public async Task AddApiKeyInQueryParams_verify_auth_scheme_handler_with_scheme_displayName_and_configureOptions()
        {
            var schemeName = "CustomScheme";
            var displayName = "DisplayName";
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInQueryParams(schemeName, displayName, _ => { }), schemeName);
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInQueryParamsHandler), scheme.HandlerType.Name);
            Assert.NotNull(scheme.DisplayName);
            Assert.Equal(displayName, scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }


        [Fact]
        public async Task AddApiKeyInQueryParams_TApiKeyProvider_verify_auth_scheme_handler_default()
        {
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInQueryParams<MockApiKeyAuthenticationService>(), ApiKeyDefaults.AuthenticationScheme);
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInQueryParamsHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
        }

        [Fact]
        public async Task AddApiKeyInQueryParams_TApiKeyProvider_verify_auth_scheme_handler_with_scheme()
        {
            var schemeName = "CustomScheme";
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInQueryParams<MockApiKeyAuthenticationService>(schemeName), schemeName);
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInQueryParamsHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        [Fact]
        public async Task AddApiKeyInQueryParams_TApiKeyProvider_verify_auth_scheme_handler_with_configureOptions()
        {
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInQueryParams<MockApiKeyAuthenticationService>(_ => { }));
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInQueryParamsHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
        }

        [Fact]
        public async Task AddApiKeyInQueryParams_TApiKeyProvider_verify_auth_scheme_handler_with_scheme_and_configureOptions()
        {
            var schemeName = "CustomScheme";
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInQueryParams<MockApiKeyAuthenticationService>(schemeName, _ => { }), schemeName);
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInQueryParamsHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        [Fact]
        public async Task AddApiKeyInQueryParams_TApiKeyProvider_verify_auth_scheme_handler_with_scheme_displayName_and_configureOptions()
        {
            var schemeName = "CustomScheme";
            var displayName = "DisplayName";
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInQueryParams<MockApiKeyAuthenticationService>(schemeName, displayName, _ => { }), schemeName);
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInQueryParamsHandler), scheme.HandlerType.Name);
            Assert.NotNull(scheme.DisplayName);
            Assert.Equal(displayName, scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        #endregion  // Verify Auth Scheme

        #region Allows Multiple Schemes

        [Fact]
        public async Task AddApiKeyInQueryParams_allows_multiple_schemes()
        {
            var schemeName = "CustomScheme";
            var displayName = "DisplayName";

            var services = new ServiceCollection();
            services.AddAuthentication()
                .AddApiKeyInQueryParams()
                .AddApiKeyInQueryParams(schemeName, displayName, _ => { });

            var sp = services.BuildServiceProvider();
            var schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
            var defaultScheme = await schemeProvider.GetSchemeAsync(ApiKeyDefaults.AuthenticationScheme);
            var scheme = await schemeProvider.GetSchemeAsync(schemeName);

            Assert.NotNull(defaultScheme);
            Assert.Equal(nameof(ApiKeyInQueryParamsHandler), defaultScheme.HandlerType.Name);
            Assert.Null(defaultScheme.DisplayName);
            Assert.Equal(ApiKeyDefaults.AuthenticationScheme, defaultScheme.Name);

            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInQueryParamsHandler), scheme.HandlerType.Name);
            Assert.NotNull(scheme.DisplayName);
            Assert.Equal(displayName, scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        [Fact]
        public async Task AddApiKeyInQueryParams_TApiKeyProvider_allows_multiple_schemes()
        {
            var schemeName = "CustomScheme";
            var displayName = "DisplayName";

            var services = new ServiceCollection();
            services.AddAuthentication()
                .AddApiKeyInQueryParams<MockApiKeyAuthenticationService>()
                .AddApiKeyInQueryParams<MockApiKeyAuthenticationService>(schemeName, displayName, _ => { });

            var sp = services.BuildServiceProvider();
            var schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
            var defaultScheme = await schemeProvider.GetSchemeAsync(ApiKeyDefaults.AuthenticationScheme);
            var scheme = await schemeProvider.GetSchemeAsync(schemeName);

            Assert.NotNull(defaultScheme);
            Assert.Equal(nameof(ApiKeyInQueryParamsHandler), defaultScheme.HandlerType.Name);
            Assert.Null(defaultScheme.DisplayName);
            Assert.Equal(ApiKeyDefaults.AuthenticationScheme, defaultScheme.Name);

            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInQueryParamsHandler), scheme.HandlerType.Name);
            Assert.NotNull(scheme.DisplayName);
            Assert.Equal(displayName, scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        #endregion  // Allows Multiple Schemes

        #region TApiKeyProvider tests

        [Fact]
        public void AddApiKeyInQueryParams_TApiKeyProvider_IApiKeyProvider_is_registered_as_transient()
        {
            var services = new ServiceCollection();
            services.AddAuthentication()
                .AddApiKeyInQueryParams<MockApiKeyAuthenticationService>();

            var serviceDescriptor = Assert.Single(services.Where(s => s.ServiceType == typeof(IApiKeyAuthenticationService)));
            Assert.Equal(typeof(IApiKeyAuthenticationService), serviceDescriptor.ServiceType);
            Assert.Equal(typeof(MockApiKeyAuthenticationService), serviceDescriptor.ImplementationType);
            Assert.Equal(ServiceLifetime.Transient, serviceDescriptor.Lifetime);

            var sp = services.BuildServiceProvider();
            var provider = sp.GetService<IApiKeyAuthenticationService>();

            Assert.NotNull(provider);
            Assert.Equal(typeof(MockApiKeyAuthenticationService), provider.GetType());
        }

        [Fact]
        public void AddApiKeyInQueryParams_TApiKeyProvider_does_not_replace_previously_user_registered_IApiKeyProvider()
        {
            var services = new ServiceCollection();
            services.AddSingleton<IApiKeyAuthenticationService, MockApiKeyProvider2>();
            services.AddAuthentication()
                .AddApiKeyInQueryParams<MockApiKeyAuthenticationService>();

            var serviceDescriptors = services.Where(s => s.ServiceType == typeof(IApiKeyAuthenticationService));
            Assert.Equal(2, serviceDescriptors.Count());

            var serviceDescriptor = Assert.Single(serviceDescriptors.Where(s => s.ImplementationType == typeof(MockApiKeyAuthenticationService)));
            Assert.Equal(typeof(IApiKeyAuthenticationService), serviceDescriptor.ServiceType);
            Assert.Equal(typeof(MockApiKeyAuthenticationService), serviceDescriptor.ImplementationType);
            Assert.Equal(ServiceLifetime.Transient, serviceDescriptor.Lifetime);

            serviceDescriptor = Assert.Single(serviceDescriptors.Where(s => s.ImplementationType == typeof(MockApiKeyProvider2)));
            Assert.Equal(typeof(IApiKeyAuthenticationService), serviceDescriptor.ServiceType);
            Assert.Equal(typeof(MockApiKeyProvider2), serviceDescriptor.ImplementationType);
            Assert.Equal(ServiceLifetime.Singleton, serviceDescriptor.Lifetime);
        }

        #endregion  // TApiKeyProvider tests

        #region Allows chaining

        [Fact]
        public void AddApiKeyInQueryParams_allows_chaining_default()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInQueryParams());
        }

        [Fact]
        public void AddApiKeyInQueryParams_allows_chaining_with_scheme()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInQueryParams(string.Empty));
        }

        [Fact]
        public void AddApiKeyInQueryParams_allows_chaining_with_configureOptions()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInQueryParams(_ => { }));
        }

        [Fact]
        public void AddApiKeyInQueryParams_allows_chaining_with_scheme_and_configureOptions()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInQueryParams(string.Empty, _ => { }));
        }

        [Fact]
        public void AddApiKeyInQueryParams_allows_chaining_with_scheme_displayName_and_configureOptions()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInQueryParams(string.Empty, string.Empty, _ => { }));
        }


        [Fact]
        public void AddApiKeyInQueryParams_TApiKeyProvider_allows_chaining()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInQueryParams<MockApiKeyAuthenticationService>());
        }

        [Fact]
        public void AddApiKeyInQueryParams_TApiKeyProvider_allows_chaining_with_scheme()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInQueryParams<MockApiKeyAuthenticationService>(string.Empty));
        }

        [Fact]
        public void AddApiKeyInQueryParams_TApiKeyProvider_allows_chaining_with_configureOptions()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInQueryParams<MockApiKeyAuthenticationService>(_ => { }));
        }

        [Fact]
        public void AddApiKeyInQueryParams_TApiKeyProvider_allows_chaining_with_scheme_and_configureOptions()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInQueryParams<MockApiKeyAuthenticationService>(string.Empty, _ => { }));
        }

        [Fact]
        public void AddApiKeyInQueryParams_TApiKeyProvider_allows_chaining_with_scheme_displayName_and_configureOptions()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInQueryParams<MockApiKeyAuthenticationService>(string.Empty, string.Empty, _ => { }));
        }

        #endregion // Allows chaining

        #endregion // API Key - In Query Parameters

        #region API Key - In Header Or Query Parameters

        #region Verify Auth Scheme

        [Fact]
        public async Task AddApiKeyInHeaderOrQueryParams_verify_auth_scheme_handler_default()
        {
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInHeaderOrQueryParams());
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInHeaderOrQueryParamsHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
        }

        [Fact]
        public async Task AddApiKeyInHeaderOrQueryParams_verify_auth_scheme_handler_with_scheme()
        {
            var schemeName = "CustomScheme";
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInHeaderOrQueryParams(schemeName), schemeName);
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInHeaderOrQueryParamsHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        [Fact]
        public async Task AddApiKeyInHeaderOrQueryParams_verify_auth_scheme_handler_with_configureOptions()
        {
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInHeaderOrQueryParams(_ => { }));
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInHeaderOrQueryParamsHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
        }

        [Fact]
        public async Task AddApiKeyInHeaderOrQueryParams_verify_auth_scheme_handler_with_scheme_and_configureOptions()
        {
            var schemeName = "CustomScheme";
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInHeaderOrQueryParams(schemeName, _ => { }), schemeName);
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInHeaderOrQueryParamsHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        [Fact]
        public async Task AddApiKeyInHeaderOrQueryParams_verify_auth_scheme_handler_with_scheme_displayName_and_configureOptions()
        {
            var schemeName = "CustomScheme";
            var displayName = "DisplayName";
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInHeaderOrQueryParams(schemeName, displayName, _ => { }), schemeName);
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInHeaderOrQueryParamsHandler), scheme.HandlerType.Name);
            Assert.NotNull(scheme.DisplayName);
            Assert.Equal(displayName, scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }


        [Fact]
        public async Task AddApiKeyInHeaderOrQueryParams_TApiKeyProvider_verify_auth_scheme_handler_default()
        {
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInHeaderOrQueryParams<MockApiKeyAuthenticationService>(), ApiKeyDefaults.AuthenticationScheme);
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInHeaderOrQueryParamsHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
        }

        [Fact]
        public async Task AddApiKeyInHeaderOrQueryParams_TApiKeyProvider_verify_auth_scheme_handler_with_scheme()
        {
            var schemeName = "CustomScheme";
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInHeaderOrQueryParams<MockApiKeyAuthenticationService>(schemeName), schemeName);
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInHeaderOrQueryParamsHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        [Fact]
        public async Task AddApiKeyInHeaderOrQueryParams_TApiKeyProvider_verify_auth_scheme_handler_with_configureOptions()
        {
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInHeaderOrQueryParams<MockApiKeyAuthenticationService>(_ => { }));
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInHeaderOrQueryParamsHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
        }

        [Fact]
        public async Task AddApiKeyInHeaderOrQueryParams_TApiKeyProvider_verify_auth_scheme_handler_with_scheme_and_configureOptions()
        {
            var schemeName = "CustomScheme";
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInHeaderOrQueryParams<MockApiKeyAuthenticationService>(schemeName, _ => { }), schemeName);
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInHeaderOrQueryParamsHandler), scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        [Fact]
        public async Task AddApiKeyInHeaderOrQueryParams_TApiKeyProvider_verify_auth_scheme_handler_with_scheme_displayName_and_configureOptions()
        {
            var schemeName = "CustomScheme";
            var displayName = "DisplayName";
            var scheme = await GetSchemeAsync(a => a.AddApiKeyInHeaderOrQueryParams<MockApiKeyAuthenticationService>(schemeName, displayName, _ => { }), schemeName);
            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInHeaderOrQueryParamsHandler), scheme.HandlerType.Name);
            Assert.NotNull(scheme.DisplayName);
            Assert.Equal(displayName, scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        #endregion  // Verify Auth Scheme

        #region Allows Multiple Schemes

        [Fact]
        public async Task AddApiKeyInHeaderOrQueryParams_allows_multiple_schemes()
        {
            var schemeName = "CustomScheme";
            var displayName = "DisplayName";

            var services = new ServiceCollection();
            services.AddAuthentication()
                .AddApiKeyInHeaderOrQueryParams()
                .AddApiKeyInHeaderOrQueryParams(schemeName, displayName, _ => { });

            var sp = services.BuildServiceProvider();
            var schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
            var defaultScheme = await schemeProvider.GetSchemeAsync(ApiKeyDefaults.AuthenticationScheme);
            var scheme = await schemeProvider.GetSchemeAsync(schemeName);

            Assert.NotNull(defaultScheme);
            Assert.Equal(nameof(ApiKeyInHeaderOrQueryParamsHandler), defaultScheme.HandlerType.Name);
            Assert.Null(defaultScheme.DisplayName);
            Assert.Equal(ApiKeyDefaults.AuthenticationScheme, defaultScheme.Name);

            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInHeaderOrQueryParamsHandler), scheme.HandlerType.Name);
            Assert.NotNull(scheme.DisplayName);
            Assert.Equal(displayName, scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        [Fact]
        public async Task AddApiKeyInHeaderOrQueryParams_TApiKeyProvider_allows_multiple_schemes()
        {
            var schemeName = "CustomScheme";
            var displayName = "DisplayName";

            var services = new ServiceCollection();
            services.AddAuthentication()
                .AddApiKeyInHeaderOrQueryParams<MockApiKeyAuthenticationService>()
                .AddApiKeyInHeaderOrQueryParams<MockApiKeyAuthenticationService>(schemeName, displayName, _ => { });

            var sp = services.BuildServiceProvider();
            var schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
            var defaultScheme = await schemeProvider.GetSchemeAsync(ApiKeyDefaults.AuthenticationScheme);
            var scheme = await schemeProvider.GetSchemeAsync(schemeName);

            Assert.NotNull(defaultScheme);
            Assert.Equal(nameof(ApiKeyInHeaderOrQueryParamsHandler), defaultScheme.HandlerType.Name);
            Assert.Null(defaultScheme.DisplayName);
            Assert.Equal(ApiKeyDefaults.AuthenticationScheme, defaultScheme.Name);

            Assert.NotNull(scheme);
            Assert.Equal(nameof(ApiKeyInHeaderOrQueryParamsHandler), scheme.HandlerType.Name);
            Assert.NotNull(scheme.DisplayName);
            Assert.Equal(displayName, scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        #endregion  // Allows Multiple Schemes

        #region TApiKeyProvider tests

        [Fact]
        public void AddApiKeyInHeaderOrQueryParams_TApiKeyProvider_IApiKeyProvider_is_registered_as_transient()
        {
            var services = new ServiceCollection();
            services.AddAuthentication()
                .AddApiKeyInHeaderOrQueryParams<MockApiKeyAuthenticationService>();

            var serviceDescriptor = Assert.Single(services.Where(s => s.ServiceType == typeof(IApiKeyAuthenticationService)));
            Assert.Equal(typeof(IApiKeyAuthenticationService), serviceDescriptor.ServiceType);
            Assert.Equal(typeof(MockApiKeyAuthenticationService), serviceDescriptor.ImplementationType);
            Assert.Equal(ServiceLifetime.Transient, serviceDescriptor.Lifetime);

            var sp = services.BuildServiceProvider();
            var provider = sp.GetService<IApiKeyAuthenticationService>();

            Assert.NotNull(provider);
            Assert.Equal(typeof(MockApiKeyAuthenticationService), provider.GetType());
        }

        [Fact]
        public void AddApiKeyInHeaderOrQueryParams_TApiKeyProvider_does_not_replace_previously_user_registered_IApiKeyProvider()
        {
            var services = new ServiceCollection();
            services.AddSingleton<IApiKeyAuthenticationService, MockApiKeyProvider2>();
            services.AddAuthentication()
                .AddApiKeyInHeaderOrQueryParams<MockApiKeyAuthenticationService>();

            var serviceDescriptors = services.Where(s => s.ServiceType == typeof(IApiKeyAuthenticationService));
            Assert.Equal(2, serviceDescriptors.Count());

            var serviceDescriptor = Assert.Single(serviceDescriptors.Where(s => s.ImplementationType == typeof(MockApiKeyAuthenticationService)));
            Assert.Equal(typeof(IApiKeyAuthenticationService), serviceDescriptor.ServiceType);
            Assert.Equal(typeof(MockApiKeyAuthenticationService), serviceDescriptor.ImplementationType);
            Assert.Equal(ServiceLifetime.Transient, serviceDescriptor.Lifetime);

            serviceDescriptor = Assert.Single(serviceDescriptors.Where(s => s.ImplementationType == typeof(MockApiKeyProvider2)));
            Assert.Equal(typeof(IApiKeyAuthenticationService), serviceDescriptor.ServiceType);
            Assert.Equal(typeof(MockApiKeyProvider2), serviceDescriptor.ImplementationType);
            Assert.Equal(ServiceLifetime.Singleton, serviceDescriptor.Lifetime);
        }

        #endregion  // TApiKeyProvider tests

        #region Allows chaining

        [Fact]
        public void AddApiKeyInHeaderOrQueryParams_allows_chaining_default()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeaderOrQueryParams());
        }

        [Fact]
        public void AddApiKeyInHeaderOrQueryParams_allows_chaining_with_scheme()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeaderOrQueryParams(string.Empty));
        }

        [Fact]
        public void AddApiKeyInHeaderOrQueryParams_allows_chaining_with_configureOptions()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeaderOrQueryParams(_ => { }));
        }

        [Fact]
        public void AddApiKeyInHeaderOrQueryParams_allows_chaining_with_scheme_and_configureOptions()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeaderOrQueryParams(string.Empty, _ => { }));
        }

        [Fact]
        public void AddApiKeyInHeaderOrQueryParams_allows_chaining_with_scheme_displayName_and_configureOptions()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeaderOrQueryParams(string.Empty, string.Empty, _ => { }));
        }


        [Fact]
        public void AddApiKeyInHeaderOrQueryParams_TApiKeyProvider_allows_chaining()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeaderOrQueryParams<MockApiKeyAuthenticationService>());
        }

        [Fact]
        public void AddApiKeyInHeaderOrQueryParams_TApiKeyProvider_allows_chaining_with_scheme()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeaderOrQueryParams<MockApiKeyAuthenticationService>(string.Empty));
        }

        [Fact]
        public void AddApiKeyInHeaderOrQueryParams_TApiKeyProvider_allows_chaining_with_configureOptions()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeaderOrQueryParams<MockApiKeyAuthenticationService>(_ => { }));
        }

        [Fact]
        public void AddApiKeyInHeaderOrQueryParams_TApiKeyProvider_allows_chaining_with_scheme_and_configureOptions()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeaderOrQueryParams<MockApiKeyAuthenticationService>(string.Empty, _ => { }));
        }

        [Fact]
        public void AddApiKeyInHeaderOrQueryParams_TApiKeyProvider_allows_chaining_with_scheme_displayName_and_configureOptions()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeaderOrQueryParams<MockApiKeyAuthenticationService>(string.Empty, string.Empty, _ => { }));
        }

        #endregion // Allows chaining

        #endregion // API Key - In Header Or Query Parameters

        private Task<AuthenticationScheme> GetSchemeAsync(Action<AuthenticationBuilder> authenticationBuilderAction, string schemeName = ApiKeyDefaults.AuthenticationScheme)
        {
            var services = new ServiceCollection();
            authenticationBuilderAction(services.AddAuthentication());
            var sp = services.BuildServiceProvider();
            var schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
            return schemeProvider.GetSchemeAsync(schemeName);
        }

        private class MockApiKeyAuthenticationService : IApiKeyAuthenticationService
        {
            public Task<IApiKey> AuthenticateAsync(string key)
            {
                throw new NotImplementedException();
            }
        }

        private class MockApiKeyProvider2 : IApiKeyAuthenticationService
        {
            public Task<IApiKey> AuthenticateAsync(string key)
            {
                throw new NotImplementedException();
            }
        }
    }
}
