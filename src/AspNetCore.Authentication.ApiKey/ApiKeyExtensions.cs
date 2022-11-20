// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.ApiKey
{
	using System;
	using Microsoft.AspNetCore.Authentication;
	using Microsoft.Extensions.DependencyInjection;
	using Microsoft.Extensions.DependencyInjection.Extensions;
	using Microsoft.Extensions.Options;

	/// <summary>
	///     Extension methods for api key authentication.
	/// </summary>
	public static class ApiKeyExtensions
	{
		/// <summary>
		///     Adds API Key - In Header authentication scheme to the project.
		///     <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate must be set on the <see cref="ApiKeyOptions.Events" />.
		/// </summary>
		/// <param name="builder"></param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInHeader(this AuthenticationBuilder builder)
		{
			return builder.AddApiKeyInHeader(ApiKeyDefaults.AuthenticationScheme);
		}

		/// <summary>
		///     Adds API Key - In Header authentication scheme to the project.
		///     <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate must be set on the <see cref="ApiKeyOptions.Events" />.
		/// </summary>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme">The authentication scheme.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInHeader(this AuthenticationBuilder builder, string authenticationScheme)
		{
			return builder.AddApiKeyInHeader(authenticationScheme, null);
		}

		/// <summary>
		///     Adds API Key - In Header authentication scheme to the project.
		///     <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate must be set on the Events property on
		///     <paramref name="configureOptions" />.
		/// </summary>
		/// <param name="builder"></param>
		/// <param name="configureOptions">The configure options.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInHeader(this AuthenticationBuilder builder, Action<ApiKeyOptions> configureOptions)
		{
			return builder.AddApiKeyInHeader(ApiKeyDefaults.AuthenticationScheme, configureOptions);
		}

		/// <summary>
		///     Adds API Key - In Header authentication scheme to the project.
		///     <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate must be set on the Events property on
		///     <paramref name="configureOptions" />.
		/// </summary>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme">The authentication scheme.</param>
		/// <param name="configureOptions">The configure options.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInHeader(this AuthenticationBuilder builder, string authenticationScheme, Action<ApiKeyOptions> configureOptions)
		{
			return builder.AddApiKeyInHeader(authenticationScheme, null, configureOptions);
		}

		/// <summary>
		///     Adds API Key - In Header authentication scheme to the project.
		///     <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate must be set on the Events property on
		///     <paramref name="configureOptions" />.
		/// </summary>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme">The authentication scheme.</param>
		/// <param name="displayName">The display name.</param>
		/// <param name="configureOptions">The configure options.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInHeader(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<ApiKeyOptions> configureOptions)
		{
			return builder.AddApiKey<ApiKeyInHeaderHandler>(authenticationScheme, displayName, configureOptions);
		}


		/// <summary>
		///     Adds API Key - In Header authentication scheme to the project. It takes a implementation of
		///     <see cref="IApiKeyAuthenticationService" /> as type parameter.
		///     If <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate is set on the <see cref="ApiKeyOptions.Events" /> then
		///     it will be used instead of implementation of <see cref="IApiKeyAuthenticationService" />.
		/// </summary>
		/// <typeparam name="TApiKeyProvider"></typeparam>
		/// <param name="builder"></param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInHeader<TApiKeyProvider>(this AuthenticationBuilder builder) where TApiKeyProvider : class, IApiKeyAuthenticationService
		{
			return builder.AddApiKeyInHeader<TApiKeyProvider>(ApiKeyDefaults.AuthenticationScheme);
		}

		/// <summary>
		///     Adds API Key - In Header authentication scheme to the project. It takes a implementation of
		///     <see cref="IApiKeyAuthenticationService" /> as type parameter.
		///     If <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate is set on the <see cref="ApiKeyOptions.Events" /> then
		///     it will be used instead of implementation of <see cref="IApiKeyAuthenticationService" />.
		/// </summary>
		/// <typeparam name="TApiKeyProvider"></typeparam>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme">The authentication scheme.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInHeader<TApiKeyProvider>(this AuthenticationBuilder builder, string authenticationScheme) where TApiKeyProvider : class, IApiKeyAuthenticationService
		{
			return builder.AddApiKeyInHeader<TApiKeyProvider>(authenticationScheme, null);
		}

		/// <summary>
		///     Adds API Key - In Header authentication scheme to the project. It takes a implementation of
		///     <see cref="IApiKeyAuthenticationService" /> as type parameter.
		///     If <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate is set on the Events property on
		///     <paramref name="configureOptions" /> then it will be used instead of implementation of
		///     <see cref="IApiKeyAuthenticationService" />.
		/// </summary>
		/// <typeparam name="TApiKeyProvider"></typeparam>
		/// <param name="builder"></param>
		/// <param name="configureOptions">The <see cref="ApiKeyOptions" />.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInHeader<TApiKeyProvider>(this AuthenticationBuilder builder, Action<ApiKeyOptions> configureOptions) where TApiKeyProvider : class, IApiKeyAuthenticationService
		{
			return builder.AddApiKeyInHeader<TApiKeyProvider>(ApiKeyDefaults.AuthenticationScheme, configureOptions);
		}

		/// <summary>
		///     Adds API Key - In Header authentication scheme to the project. It takes a implementation of
		///     <see cref="IApiKeyAuthenticationService" /> as type parameter.
		///     If <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate is set on the Events property on
		///     <paramref name="configureOptions" /> then it will be used instead of implementation of
		///     <see cref="IApiKeyAuthenticationService" />.
		/// </summary>
		/// <typeparam name="TApiKeyProvider"></typeparam>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme">The authentication scheme.</param>
		/// <param name="configureOptions">The <see cref="ApiKeyOptions" />.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInHeader<TApiKeyProvider>(this AuthenticationBuilder builder, string authenticationScheme, Action<ApiKeyOptions> configureOptions) where TApiKeyProvider : class, IApiKeyAuthenticationService
		{
			return builder.AddApiKeyInHeader<TApiKeyProvider>(authenticationScheme, null, configureOptions);
		}

		/// <summary>
		///     Adds API Key - In Header authentication scheme to the project. It takes a implementation of
		///     <see cref="IApiKeyAuthenticationService" /> as type parameter.
		///     If <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate is set on the Events property on
		///     <paramref name="configureOptions" /> then it will be used instead of implementation of
		///     <see cref="IApiKeyAuthenticationService" />.
		/// </summary>
		/// <typeparam name="TApiKeyProvider"></typeparam>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme">The authentication scheme.</param>
		/// <param name="displayName">The display name.</param>
		/// <param name="configureOptions">The <see cref="ApiKeyOptions" />.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInHeader<TApiKeyProvider>(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<ApiKeyOptions> configureOptions) where TApiKeyProvider : class, IApiKeyAuthenticationService
		{
			return builder.AddApiKey<TApiKeyProvider, ApiKeyInHeaderHandler>(authenticationScheme, displayName, configureOptions);
		}

		/// <summary>
		///     Adds API Key - In Authorization Header authentication scheme to the project.
		///     <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate must be set on the <see cref="ApiKeyOptions.Events" />.
		/// </summary>
		/// <param name="builder"></param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInAuthorizationHeader(this AuthenticationBuilder builder)
		{
			return builder.AddApiKeyInAuthorizationHeader(ApiKeyDefaults.AuthenticationScheme);
		}

		/// <summary>
		///     Adds API Key - In Authorization Header authentication scheme to the project.
		///     <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate must be set on the <see cref="ApiKeyOptions.Events" />.
		/// </summary>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme">The authentication scheme.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInAuthorizationHeader(this AuthenticationBuilder builder, string authenticationScheme)
		{
			return builder.AddApiKeyInAuthorizationHeader(authenticationScheme, null);
		}

		/// <summary>
		///     Adds API Key - In Authorization Header authentication scheme to the project.
		///     <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate must be set on the Events property on
		///     <paramref name="configureOptions" />.
		/// </summary>
		/// <param name="builder"></param>
		/// <param name="configureOptions">The configure options.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInAuthorizationHeader(this AuthenticationBuilder builder, Action<ApiKeyOptions> configureOptions)
		{
			return builder.AddApiKeyInAuthorizationHeader(ApiKeyDefaults.AuthenticationScheme, configureOptions);
		}

		/// <summary>
		///     Adds API Key - In Authorization Header authentication scheme to the project.
		///     <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate must be set on the Events property on
		///     <paramref name="configureOptions" />.
		/// </summary>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme">The authentication scheme.</param>
		/// <param name="configureOptions">The configure options.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInAuthorizationHeader(this AuthenticationBuilder builder, string authenticationScheme, Action<ApiKeyOptions> configureOptions)
		{
			return builder.AddApiKeyInAuthorizationHeader(authenticationScheme, null, configureOptions);
		}

		/// <summary>
		///     Adds API Key - In Authorization Header authentication scheme to the project.
		///     <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate must be set on the Events property on
		///     <paramref name="configureOptions" />.
		/// </summary>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme">The authentication scheme.</param>
		/// <param name="displayName">The display name.</param>
		/// <param name="configureOptions">The configure options.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInAuthorizationHeader(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<ApiKeyOptions> configureOptions)
		{
			return builder.AddApiKey<ApiKeyInAuthorizationHeaderHandler>(authenticationScheme, displayName, configureOptions);
		}


		/// <summary>
		///     Adds API Key - In Authorization Header authentication scheme to the project. It takes a implementation of
		///     <see cref="IApiKeyAuthenticationService" /> as type parameter.
		///     If <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate is set on the <see cref="ApiKeyOptions.Events" /> then
		///     it will be used instead of implementation of <see cref="IApiKeyAuthenticationService" />.
		/// </summary>
		/// <typeparam name="TApiKeyProvider"></typeparam>
		/// <param name="builder"></param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInAuthorizationHeader<TApiKeyProvider>(this AuthenticationBuilder builder) where TApiKeyProvider : class, IApiKeyAuthenticationService
		{
			return builder.AddApiKeyInAuthorizationHeader<TApiKeyProvider>(ApiKeyDefaults.AuthenticationScheme);
		}

		/// <summary>
		///     Adds API Key - In Authorization Header authentication scheme to the project. It takes a implementation of
		///     <see cref="IApiKeyAuthenticationService" /> as type parameter.
		///     If <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate is set on the <see cref="ApiKeyOptions.Events" /> then
		///     it will be used instead of implementation of <see cref="IApiKeyAuthenticationService" />.
		/// </summary>
		/// <typeparam name="TApiKeyProvider"></typeparam>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme">The authentication scheme.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInAuthorizationHeader<TApiKeyProvider>(this AuthenticationBuilder builder, string authenticationScheme) where TApiKeyProvider : class, IApiKeyAuthenticationService
		{
			return builder.AddApiKeyInAuthorizationHeader<TApiKeyProvider>(authenticationScheme, null);
		}

		/// <summary>
		///     Adds API Key - In Authorization Header authentication scheme to the project. It takes a implementation of
		///     <see cref="IApiKeyAuthenticationService" /> as type parameter.
		///     If <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate is set on the Events property on
		///     <paramref name="configureOptions" /> then it will be used instead of implementation of
		///     <see cref="IApiKeyAuthenticationService" />.
		/// </summary>
		/// <typeparam name="TApiKeyProvider"></typeparam>
		/// <param name="builder"></param>
		/// <param name="configureOptions">The <see cref="ApiKeyOptions" />.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInAuthorizationHeader<TApiKeyProvider>(this AuthenticationBuilder builder, Action<ApiKeyOptions> configureOptions) where TApiKeyProvider : class, IApiKeyAuthenticationService
		{
			return builder.AddApiKeyInAuthorizationHeader<TApiKeyProvider>(ApiKeyDefaults.AuthenticationScheme, configureOptions);
		}

		/// <summary>
		///     Adds API Key - In Authorization Header authentication scheme to the project. It takes a implementation of
		///     <see cref="IApiKeyAuthenticationService" /> as type parameter.
		///     If <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate is set on the Events property on
		///     <paramref name="configureOptions" /> then it will be used instead of implementation of
		///     <see cref="IApiKeyAuthenticationService" />.
		/// </summary>
		/// <typeparam name="TApiKeyProvider"></typeparam>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme">The authentication scheme.</param>
		/// <param name="configureOptions">The <see cref="ApiKeyOptions" />.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInAuthorizationHeader<TApiKeyProvider>(this AuthenticationBuilder builder, string authenticationScheme, Action<ApiKeyOptions> configureOptions) where TApiKeyProvider : class, IApiKeyAuthenticationService
		{
			return builder.AddApiKeyInAuthorizationHeader<TApiKeyProvider>(authenticationScheme, null, configureOptions);
		}

		/// <summary>
		///     Adds API Key - In Authorization Header authentication scheme to the project. It takes a implementation of
		///     <see cref="IApiKeyAuthenticationService" /> as type parameter.
		///     If <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate is set on the Events property on
		///     <paramref name="configureOptions" /> then it will be used instead of implementation of
		///     <see cref="IApiKeyAuthenticationService" />.
		/// </summary>
		/// <typeparam name="TApiKeyProvider"></typeparam>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme">The authentication scheme.</param>
		/// <param name="displayName">The display name.</param>
		/// <param name="configureOptions">The <see cref="ApiKeyOptions" />.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInAuthorizationHeader<TApiKeyProvider>(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<ApiKeyOptions> configureOptions) where TApiKeyProvider : class, IApiKeyAuthenticationService
		{
			return builder.AddApiKey<TApiKeyProvider, ApiKeyInAuthorizationHeaderHandler>(authenticationScheme, displayName, configureOptions);
		}

		/// <summary>
		///     Adds API Key - In Query Parameters authentication scheme to the project.
		///     <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate must be set on the <see cref="ApiKeyOptions.Events" />.
		/// </summary>
		/// <param name="builder"></param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInQueryParams(this AuthenticationBuilder builder)
		{
			return builder.AddApiKeyInQueryParams(ApiKeyDefaults.AuthenticationScheme);
		}

		/// <summary>
		///     Adds API Key - In Query Parameters authentication scheme to the project.
		///     <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate must be set on the <see cref="ApiKeyOptions.Events" />.
		/// </summary>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme">The authentication scheme.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInQueryParams(this AuthenticationBuilder builder, string authenticationScheme)
		{
			return builder.AddApiKeyInQueryParams(authenticationScheme, null);
		}

		/// <summary>
		///     Adds API Key - In Query Parameters authentication scheme to the project.
		///     <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate must be set on the Events property on
		///     <paramref name="configureOptions" />.
		/// </summary>
		/// <param name="builder"></param>
		/// <param name="configureOptions">The configure options.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInQueryParams(this AuthenticationBuilder builder, Action<ApiKeyOptions> configureOptions)
		{
			return builder.AddApiKeyInQueryParams(ApiKeyDefaults.AuthenticationScheme, configureOptions);
		}

		/// <summary>
		///     Adds API Key - In Query Parameters authentication scheme to the project.
		///     <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate must be set on the Events property on
		///     <paramref name="configureOptions" />.
		/// </summary>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme">The authentication scheme.</param>
		/// <param name="configureOptions">The configure options.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInQueryParams(this AuthenticationBuilder builder, string authenticationScheme, Action<ApiKeyOptions> configureOptions)
		{
			return builder.AddApiKeyInQueryParams(authenticationScheme, null, configureOptions);
		}

		/// <summary>
		///     Adds API Key - In Query Parameters authentication scheme to the project.
		///     <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate must be set on the Events property on
		///     <paramref name="configureOptions" />.
		/// </summary>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme">The authentication scheme.</param>
		/// <param name="displayName">The display name.</param>
		/// <param name="configureOptions">The configure options.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInQueryParams(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<ApiKeyOptions> configureOptions)
		{
			return builder.AddApiKey<ApiKeyInQueryParamsHandler>(authenticationScheme, displayName, configureOptions);
		}


		/// <summary>
		///     Adds API Key - In Query Parameters authentication scheme to the project. It takes a implementation of
		///     <see cref="IApiKeyAuthenticationService" /> as type parameter.
		///     If <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate is set on the <see cref="ApiKeyOptions.Events" /> then
		///     it will be used instead of implementation of <see cref="IApiKeyAuthenticationService" />.
		/// </summary>
		/// <typeparam name="TApiKeyProvider"></typeparam>
		/// <param name="builder"></param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInQueryParams<TApiKeyProvider>(this AuthenticationBuilder builder) where TApiKeyProvider : class, IApiKeyAuthenticationService
		{
			return builder.AddApiKeyInQueryParams<TApiKeyProvider>(ApiKeyDefaults.AuthenticationScheme);
		}

		/// <summary>
		///     Adds API Key - In Query Parameters authentication scheme to the project. It takes a implementation of
		///     <see cref="IApiKeyAuthenticationService" /> as type parameter.
		///     If <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate is set on the <see cref="ApiKeyOptions.Events" /> then
		///     it will be used instead of implementation of <see cref="IApiKeyAuthenticationService" />.
		/// </summary>
		/// <typeparam name="TApiKeyProvider"></typeparam>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme">The authentication scheme.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInQueryParams<TApiKeyProvider>(this AuthenticationBuilder builder, string authenticationScheme) where TApiKeyProvider : class, IApiKeyAuthenticationService
		{
			return builder.AddApiKeyInQueryParams<TApiKeyProvider>(authenticationScheme, null);
		}

		/// <summary>
		///     Adds API Key - In Query Parameters authentication scheme to the project. It takes a implementation of
		///     <see cref="IApiKeyAuthenticationService" /> as type parameter.
		///     If <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate is set on the Events property on
		///     <paramref name="configureOptions" /> then it will be used instead of implementation of
		///     <see cref="IApiKeyAuthenticationService" />.
		/// </summary>
		/// <typeparam name="TApiKeyProvider"></typeparam>
		/// <param name="builder"></param>
		/// <param name="configureOptions">The <see cref="ApiKeyOptions" />.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInQueryParams<TApiKeyProvider>(this AuthenticationBuilder builder, Action<ApiKeyOptions> configureOptions) where TApiKeyProvider : class, IApiKeyAuthenticationService
		{
			return builder.AddApiKeyInQueryParams<TApiKeyProvider>(ApiKeyDefaults.AuthenticationScheme, configureOptions);
		}

		/// <summary>
		///     Adds API Key - In Query Parameters authentication scheme to the project. It takes a implementation of
		///     <see cref="IApiKeyAuthenticationService" /> as type parameter.
		///     If <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate is set on the Events property on
		///     <paramref name="configureOptions" /> then it will be used instead of implementation of
		///     <see cref="IApiKeyAuthenticationService" />.
		/// </summary>
		/// <typeparam name="TApiKeyProvider"></typeparam>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme">The authentication scheme.</param>
		/// <param name="configureOptions">The <see cref="ApiKeyOptions" />.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInQueryParams<TApiKeyProvider>(this AuthenticationBuilder builder, string authenticationScheme, Action<ApiKeyOptions> configureOptions) where TApiKeyProvider : class, IApiKeyAuthenticationService
		{
			return builder.AddApiKeyInQueryParams<TApiKeyProvider>(authenticationScheme, null, configureOptions);
		}

		/// <summary>
		///     Adds API Key - In Query Parameters authentication scheme to the project. It takes a implementation of
		///     <see cref="IApiKeyAuthenticationService" /> as type parameter.
		///     If <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate is set on the Events property on
		///     <paramref name="configureOptions" /> then it will be used instead of implementation of
		///     <see cref="IApiKeyAuthenticationService" />.
		/// </summary>
		/// <typeparam name="TApiKeyProvider"></typeparam>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme">The authentication scheme.</param>
		/// <param name="displayName">The display name.</param>
		/// <param name="configureOptions">The <see cref="ApiKeyOptions" />.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInQueryParams<TApiKeyProvider>(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<ApiKeyOptions> configureOptions) where TApiKeyProvider : class, IApiKeyAuthenticationService
		{
			return builder.AddApiKey<TApiKeyProvider, ApiKeyInQueryParamsHandler>(authenticationScheme, displayName, configureOptions);
		}

		/// <summary>
		///     Adds API Key - In Header Or Query Parameters authentication scheme to the project.
		///     <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate must be set on the <see cref="ApiKeyOptions.Events" />.
		/// </summary>
		/// <param name="builder"></param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInHeaderOrQueryParams(this AuthenticationBuilder builder)
		{
			return builder.AddApiKeyInHeaderOrQueryParams(ApiKeyDefaults.AuthenticationScheme);
		}

		/// <summary>
		///     Adds API Key - In Header Or Query Parameters authentication scheme to the project.
		///     <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate must be set on the <see cref="ApiKeyOptions.Events" />.
		/// </summary>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme">The authentication scheme.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInHeaderOrQueryParams(this AuthenticationBuilder builder, string authenticationScheme)
		{
			return builder.AddApiKeyInHeaderOrQueryParams(authenticationScheme, null);
		}

		/// <summary>
		///     Adds API Key - In Header Or Query Parameters authentication scheme to the project.
		///     <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate must be set on the Events property on
		///     <paramref name="configureOptions" />.
		/// </summary>
		/// <param name="builder"></param>
		/// <param name="configureOptions">The configure options.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInHeaderOrQueryParams(this AuthenticationBuilder builder, Action<ApiKeyOptions> configureOptions)
		{
			return builder.AddApiKeyInHeaderOrQueryParams(ApiKeyDefaults.AuthenticationScheme, configureOptions);
		}

		/// <summary>
		///     Adds API Key - In Header Or Query Parameters authentication scheme to the project.
		///     <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate must be set on the Events property on
		///     <paramref name="configureOptions" />.
		/// </summary>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme">The authentication scheme.</param>
		/// <param name="configureOptions">The configure options.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInHeaderOrQueryParams(this AuthenticationBuilder builder, string authenticationScheme, Action<ApiKeyOptions> configureOptions)
		{
			return builder.AddApiKeyInHeaderOrQueryParams(authenticationScheme, null, configureOptions);
		}

		/// <summary>
		///     Adds API Key - In Header Or Query Parameters authentication scheme to the project.
		///     <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate must be set on the Events property on
		///     <paramref name="configureOptions" />.
		/// </summary>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme">The authentication scheme.</param>
		/// <param name="displayName">The display name.</param>
		/// <param name="configureOptions">The configure options.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInHeaderOrQueryParams(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<ApiKeyOptions> configureOptions)
		{
			return builder.AddApiKey<ApiKeyInHeaderOrQueryParamsHandler>(authenticationScheme, displayName, configureOptions);
		}


		/// <summary>
		///     Adds API Key - In Header Or Query Parameters authentication scheme to the project. It takes a implementation of
		///     <see cref="IApiKeyAuthenticationService" /> as type parameter.
		///     If <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate is set on the <see cref="ApiKeyOptions.Events" /> then
		///     it will be used instead of implementation of <see cref="IApiKeyAuthenticationService" />.
		/// </summary>
		/// <typeparam name="TApiKeyProvider"></typeparam>
		/// <param name="builder"></param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInHeaderOrQueryParams<TApiKeyProvider>(this AuthenticationBuilder builder) where TApiKeyProvider : class, IApiKeyAuthenticationService
		{
			return builder.AddApiKeyInHeaderOrQueryParams<TApiKeyProvider>(ApiKeyDefaults.AuthenticationScheme);
		}

		/// <summary>
		///     Adds API Key - In Header Or Query Parameters authentication scheme to the project. It takes a implementation of
		///     <see cref="IApiKeyAuthenticationService" /> as type parameter.
		///     If <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate is set on the <see cref="ApiKeyOptions.Events" /> then
		///     it will be used instead of implementation of <see cref="IApiKeyAuthenticationService" />.
		/// </summary>
		/// <typeparam name="TApiKeyProvider"></typeparam>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme">The authentication scheme.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInHeaderOrQueryParams<TApiKeyProvider>(this AuthenticationBuilder builder, string authenticationScheme) where TApiKeyProvider : class, IApiKeyAuthenticationService
		{
			return builder.AddApiKeyInHeaderOrQueryParams<TApiKeyProvider>(authenticationScheme, null);
		}

		/// <summary>
		///     Adds API Key - In Header Or Query Parameters authentication scheme to the project. It takes a implementation of
		///     <see cref="IApiKeyAuthenticationService" /> as type parameter.
		///     If <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate is set on the Events property on
		///     <paramref name="configureOptions" /> then it will be used instead of implementation of
		///     <see cref="IApiKeyAuthenticationService" />.
		/// </summary>
		/// <typeparam name="TApiKeyProvider"></typeparam>
		/// <param name="builder"></param>
		/// <param name="configureOptions">The <see cref="ApiKeyOptions" />.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInHeaderOrQueryParams<TApiKeyProvider>(this AuthenticationBuilder builder, Action<ApiKeyOptions> configureOptions) where TApiKeyProvider : class, IApiKeyAuthenticationService
		{
			return builder.AddApiKeyInHeaderOrQueryParams<TApiKeyProvider>(ApiKeyDefaults.AuthenticationScheme, configureOptions);
		}

		/// <summary>
		///     Adds API Key - In Header Or Query Parameters authentication scheme to the project. It takes a implementation of
		///     <see cref="IApiKeyAuthenticationService" /> as type parameter.
		///     If <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate is set on the Events property on
		///     <paramref name="configureOptions" /> then it will be used instead of implementation of
		///     <see cref="IApiKeyAuthenticationService" />.
		/// </summary>
		/// <typeparam name="TApiKeyProvider"></typeparam>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme">The authentication scheme.</param>
		/// <param name="configureOptions">The <see cref="ApiKeyOptions" />.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInHeaderOrQueryParams<TApiKeyProvider>(this AuthenticationBuilder builder, string authenticationScheme, Action<ApiKeyOptions> configureOptions) where TApiKeyProvider : class, IApiKeyAuthenticationService
		{
			return builder.AddApiKeyInHeaderOrQueryParams<TApiKeyProvider>(authenticationScheme, null, configureOptions);
		}

		/// <summary>
		///     Adds API Key - In Header Or Query Parameters authentication scheme to the project. It takes a implementation of
		///     <see cref="IApiKeyAuthenticationService" /> as type parameter.
		///     If <see cref="Events.ApiKeyEvents.OnValidateKey" /> delegate is set on the Events property on
		///     <paramref name="configureOptions" /> then it will be used instead of implementation of
		///     <see cref="IApiKeyAuthenticationService" />.
		/// </summary>
		/// <typeparam name="TApiKeyProvider"></typeparam>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme">The authentication scheme.</param>
		/// <param name="displayName">The display name.</param>
		/// <param name="configureOptions">The <see cref="ApiKeyOptions" />.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddApiKeyInHeaderOrQueryParams<TApiKeyProvider>(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<ApiKeyOptions> configureOptions) where TApiKeyProvider : class, IApiKeyAuthenticationService
		{
			return builder.AddApiKey<TApiKeyProvider, ApiKeyInHeaderOrQueryParamsHandler>(authenticationScheme, displayName, configureOptions);
		}


		private static AuthenticationBuilder AddApiKey<TApiKeyHandler>(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<ApiKeyOptions> configureOptions)
			where TApiKeyHandler : AuthenticationHandler<ApiKeyOptions>
		{
			// Add the authentication scheme name for the specific options.
			builder.Services.Configure<ApiKeyOptions>(
				authenticationScheme,
				o => o.AuthenticationSchemeName = authenticationScheme);

			// Adds post configure options to the pipeline.
			builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<ApiKeyOptions>, ApiKeyPostConfigureOptions>());

			// Adds api key authentication scheme to the pipeline.
			return builder.AddScheme<ApiKeyOptions, TApiKeyHandler>(authenticationScheme, displayName, configureOptions);
		}

		private static AuthenticationBuilder AddApiKey<TApiKeyProvider, TApiKeyHandler>(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<ApiKeyOptions> configureOptions)
			where TApiKeyProvider : class, IApiKeyAuthenticationService
			where TApiKeyHandler : AuthenticationHandler<ApiKeyOptions>
		{
			// Adds implementation of IApiKeyProvider to the dependency container.
			builder.Services.AddTransient<IApiKeyAuthenticationService, TApiKeyProvider>();

			// Add the authentication scheme name for the specific options.
			builder.Services.Configure<ApiKeyOptions>(
				authenticationScheme,
				o =>
				{
					o.AuthenticationSchemeName = authenticationScheme;
					o.ApiKeyProviderType = typeof(TApiKeyProvider);
				});

			// Adds post configure options to the pipeline.
			builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<ApiKeyOptions>, ApiKeyPostConfigureOptions>());

			// Adds api key authentication scheme to the pipeline.
			return builder.AddScheme<ApiKeyOptions, TApiKeyHandler>(authenticationScheme, displayName, configureOptions);
		}
	}
}
