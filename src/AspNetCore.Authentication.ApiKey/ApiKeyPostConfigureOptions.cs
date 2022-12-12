// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.ApiKey
{
	using System;
	using Microsoft.Extensions.DependencyInjection;
	using Microsoft.Extensions.Options;

	/// <summary>
	///     This post configure options checks whether the required option properties are set or not on
	///     <see cref="ApiKeyOptions" />.
	/// </summary>
	internal sealed class ApiKeyPostConfigureOptions : IPostConfigureOptions<ApiKeyOptions>
	{
		private readonly IServiceProvider serviceProvider;

		public ApiKeyPostConfigureOptions(IServiceProvider serviceProvider)
		{
			this.serviceProvider = serviceProvider;
		}

		public void PostConfigure(string name, ApiKeyOptions options)
		{
			if(!options.SuppressWWWAuthenticateHeader && string.IsNullOrWhiteSpace(options.Realm))
			{
				throw new InvalidOperationException($"{nameof(ApiKeyOptions.Realm)} must be set in {nameof(ApiKeyOptions)} when setting up the authentication.");
			}

			if(string.IsNullOrWhiteSpace(options.KeyName))
			{
				throw new InvalidOperationException($"{nameof(ApiKeyOptions.KeyName)} must be set in {nameof(ApiKeyOptions)} when setting up the authentication.");
			}

			IApiKeyAuthenticationServiceFactory apiKeyProviderFactory = this.serviceProvider.GetService<IApiKeyAuthenticationServiceFactory>();
			if(options.Events?.OnValidateKey == null && options.EventsType == null && options.ApiKeyProviderType == null && apiKeyProviderFactory == null)
			{
				throw new InvalidOperationException($"Either {nameof(ApiKeyOptions.Events.OnValidateKey)} delegate on configure options {nameof(ApiKeyOptions.Events)} should be set or use an extension method with type parameter of type {nameof(IApiKeyAuthenticationService)} or register an implementation of type {nameof(IApiKeyAuthenticationServiceFactory)} in the service collection.");
			}
		}
	}
}
