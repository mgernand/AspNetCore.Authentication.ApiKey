﻿// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.ApiKey
{
    using System;
    using System.Text.Encodings.Web;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Logging;
    using Microsoft.Extensions.Options;
    using Microsoft.Net.Http.Headers;

    /// <summary>
	/// Inherited from <see cref="AuthenticationHandler{TOptions}"/> for api key authentication.
	/// </summary>
	public abstract class ApiKeyHandlerBase : AuthenticationHandler<ApiKeyOptions>
	{
		protected ApiKeyHandlerBase(IOptionsMonitor<ApiKeyOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
			: base(options, logger, encoder, clock)
		{
		}

		private string Challenge => $"{GetWwwAuthenticateSchemeName()} realm=\"{Options.Realm}\", charset=\"UTF-8\", in=\"{GetWwwAuthenticateInParameter()}\", key_name=\"{Options.KeyName}\"";

		/// <summary>
		/// Get or set <see cref="ApiKey.Events.ApiKeyEvents"/>.
		/// </summary>
		protected new MadEyeMatt.AspNetCore.Authentication.ApiKey.Events.ApiKeyEvents Events { get => (MadEyeMatt.AspNetCore.Authentication.ApiKey.Events.ApiKeyEvents)base.Events; set => base.Events = value; }

		/// <summary>
		/// Create an instance of <see cref="ApiKey.Events.ApiKeyEvents"/>.
		/// </summary>
		/// <returns></returns>
		protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new MadEyeMatt.AspNetCore.Authentication.ApiKey.Events.ApiKeyEvents());

		protected abstract Task<string> ParseApiKeyAsync();

		protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
		{
			if (IgnoreAuthenticationIfAllowAnonymous())
			{
				Logger.LogDebug("AllowAnonymous found on the endpoint so request was not authenticated.");
				return AuthenticateResult.NoResult();
			}

			var apiKey = string.Empty;
			try
			{
				apiKey = await ParseApiKeyAsync().ConfigureAwait(false);
			}
			catch (Exception exception)
			{
				Logger.LogError(exception, "Error parsing api key.");
				return AuthenticateResult.Fail("Error parsing api key." + Environment.NewLine + exception.Message);
			}

			if (string.IsNullOrWhiteSpace(apiKey))
			{
				Logger.LogInformation("No Api Key found in the request.");
				return AuthenticateResult.NoResult();
			}

			try
			{
				var validateCredentialsResult = await RaiseAndHandleEventValidateKeyAsync(apiKey).ConfigureAwait(false);
				if (validateCredentialsResult != null)
				{
					// If result is set then return it.
					return validateCredentialsResult;
				}

				// Validate using the implementation of IApiKeyProvider.
				var validatedApiKey = await ValidateUsingApiKeyProviderAsync(apiKey).ConfigureAwait(false);
				if (validatedApiKey == null
					|| (!Options.ForLegacyIgnoreExtraValidatedApiKeyCheck && !string.Equals(validatedApiKey.Key, apiKey, StringComparison.OrdinalIgnoreCase))
				)
				{
					Logger.LogError($"Invalid API Key provided by {nameof(IApiKeyAuthenticationService)}.");
					return AuthenticateResult.Fail($"Invalid API Key provided by {nameof(IApiKeyAuthenticationService)}.");
				}

				return await RaiseAndHandleAuthenticationSucceededAsync(validatedApiKey).ConfigureAwait(false);
			}
			catch (Exception exception)
			{
				var authenticationFailedContext = new MadEyeMatt.AspNetCore.Authentication.ApiKey.Events.ApiKeyAuthenticationFailedContext(Context, Scheme, Options, exception);
				await Events.AuthenticationFailedAsync(authenticationFailedContext).ConfigureAwait(false);

				if (authenticationFailedContext.Result != null)
				{
					return authenticationFailedContext.Result;
				}

				throw;
			}
		}

		/// <inheritdoc/>
		protected override async Task HandleForbiddenAsync(AuthenticationProperties properties)
		{
			// Raise handle forbidden event.
			var handleForbiddenContext = new MadEyeMatt.AspNetCore.Authentication.ApiKey.Events.ApiKeyHandleForbiddenContext(Context, Scheme, Options, properties);
			await Events.HandleForbiddenAsync(handleForbiddenContext).ConfigureAwait(false);
			if (handleForbiddenContext.IsHandled)
			{
				return;
			}

			await base.HandleForbiddenAsync(properties);
		}

		/// <summary>
		/// Handles the un-authenticated requests. 
		/// Returns 401 status code in response.
		/// If <see cref="ApiKeyOptions.SuppressWWWAuthenticateHeader"/> is not set then,
		/// adds 'WWW-Authenticate' response header with KeyName as authentication scheme and 'Realm' 
		/// to let the client know which authentication scheme is being used by the system.
		/// </summary>
		/// <param name="properties"><see cref="AuthenticationProperties"/></param>
		/// <returns>A Task.</returns>
		protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
		{
			// Raise handle challenge event.
			var handleChallengeContext = new MadEyeMatt.AspNetCore.Authentication.ApiKey.Events.ApiKeyHandleChallengeContext(Context, Scheme, Options, properties);
			await Events.HandleChallengeAsync(handleChallengeContext).ConfigureAwait(false);
			if (handleChallengeContext.IsHandled)
			{
				return;
			}

			if (!Options.SuppressWWWAuthenticateHeader)
			{
				Response.Headers[HeaderNames.WWWAuthenticate] = Challenge;
			}
			await base.HandleChallengeAsync(properties);
		}

		private async Task<AuthenticateResult> RaiseAndHandleEventValidateKeyAsync(string apiKey)
		{
			var validateApiContext = new MadEyeMatt.AspNetCore.Authentication.ApiKey.Events.ApiKeyValidateKeyContext(Context, Scheme, Options, apiKey);
			await Events.ValidateKeyAsync(validateApiContext).ConfigureAwait(false);

			if (validateApiContext.Result != null)
			{
				return validateApiContext.Result;
			}

			if (validateApiContext.Principal?.Identity != null && validateApiContext.Principal.Identity.IsAuthenticated)
			{
				// If claims principal is set and is authenticated then build a ticket by calling and return success.
				validateApiContext.Success();
				return validateApiContext.Result;
			}

			return null;
		}

		private async Task<AuthenticateResult> RaiseAndHandleAuthenticationSucceededAsync(IApiKey apiKey)
		{
			// ..create claims principal.
			var principal = ApiKeyUtils.BuildClaimsPrincipal(apiKey.OwnerName, Scheme.Name, ClaimsIssuer, apiKey.Claims);

			// Raise authentication succeeded event.
			var authenticationSucceededContext = new MadEyeMatt.AspNetCore.Authentication.ApiKey.Events.ApiKeyAuthenticationSucceededContext(Context, Scheme, Options, principal);
			await Events.AuthenticationSucceededAsync(authenticationSucceededContext).ConfigureAwait(false);

			if (authenticationSucceededContext.Result != null)
			{
				return authenticationSucceededContext.Result;
			}

			if (authenticationSucceededContext.Principal?.Identity != null && authenticationSucceededContext.Principal.Identity.IsAuthenticated)
			{
				// If claims principal is set and is authenticated then build a ticket by calling and return success.
				authenticationSucceededContext.Success();
				return authenticationSucceededContext.Result;
			}

			Logger.LogError("No authenticated principal set.");
			return AuthenticateResult.Fail("No authenticated principal set.");
		}

		private async Task<IApiKey> ValidateUsingApiKeyProviderAsync(string apiKey)
		{
			IApiKeyAuthenticationService apiKeyAuthenticationService = null;

			// Try to get an instance of the IBasicUserValidationServiceFactory.
			var apiKeyProviderFactory = this.Context.RequestServices.GetService<IApiKeyAuthenticationServiceFactory>();

			// Try to get a IApiKeyProvider instance from the factory.
			apiKeyAuthenticationService = apiKeyProviderFactory?.CreateApiKeyAuthenticationService(Options.AuthenticationSchemeName);

			if (apiKeyAuthenticationService == null && Options.ApiKeyProviderType != null)
			{
				apiKeyAuthenticationService = ActivatorUtilities.GetServiceOrCreateInstance(Context.RequestServices, Options.ApiKeyProviderType) as IApiKeyAuthenticationService;
			}

			if (apiKeyAuthenticationService == null)
			{
				throw new InvalidOperationException($"Either {nameof(Options.Events.OnValidateKey)} delegate on configure options {nameof(Options.Events)} should be set or use an extension method with type parameter of type {nameof(IApiKeyAuthenticationService)} or register an implementation of type {nameof(IApiKeyAuthenticationServiceFactory)} in the service collection.");
			}

			try
			{
				return await apiKeyAuthenticationService.AuthenticateAsync(apiKey).ConfigureAwait(false);
			}
			finally
			{
				if (apiKeyAuthenticationService is IDisposable disposableApiKeyProvider)
				{
					disposableApiKeyProvider.Dispose();
				}
			}
		}

		private string GetWwwAuthenticateSchemeName()
        {
			return Options.ForLegacyUseKeyNameAsSchemeNameOnWWWAuthenticateHeader
				? Options.KeyName
				: Scheme.Name;
        }

		private string GetWwwAuthenticateInParameter()
        {
			var handlerType = this.GetType();

			if (handlerType == typeof(ApiKeyInAuthorizationHeaderHandler))
				return "authorization_header";
			if (handlerType == typeof(ApiKeyInHeaderHandler))
				return "header";
			if (handlerType == typeof(ApiKeyInQueryParamsHandler))
				return "query_params";
			if (handlerType == typeof(ApiKeyInHeaderOrQueryParamsHandler))
				return "header_or_query_params";

			throw new NotImplementedException($"No parameter name defined for {handlerType.FullName}.");
		}

		private bool IgnoreAuthenticationIfAllowAnonymous()
		{
#if (NET461 || NETSTANDARD2_0)
			return false;
#else
			return Options.IgnoreAuthenticationIfAllowAnonymous
				&& Context.GetEndpoint()?.Metadata?.GetMetadata<Microsoft.AspNetCore.Authorization.IAllowAnonymous>() != null;
#endif
		}
	}
}
