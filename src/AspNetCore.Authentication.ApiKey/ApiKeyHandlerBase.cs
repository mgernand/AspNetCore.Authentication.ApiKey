// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.ApiKey
{
	using System;
	using System.Security.Claims;
	using System.Text.Encodings.Web;
	using System.Threading.Tasks;
	using MadEyeMatt.AspNetCore.Authentication.ApiKey.Events;
	using Microsoft.AspNetCore.Authentication;
	using Microsoft.AspNetCore.Http;
	using Microsoft.Extensions.DependencyInjection;
	using Microsoft.Extensions.Logging;
	using Microsoft.Extensions.Options;
	using Microsoft.Net.Http.Headers;

	/// <summary>
	///     Inherited from <see cref="AuthenticationHandler{TOptions}" /> for api key authentication.
	/// </summary>
	public abstract class ApiKeyHandlerBase : AuthenticationHandler<ApiKeyOptions>
	{
#if NET8_0_OR_GREATER
		/// <summary>
		///		Initializes a new instance of the <see cref="ApiKeyHandlerBase"/> type.
		/// </summary>
		/// <param name="options"></param>
		/// <param name="logger"></param>
		/// <param name="encoder"></param>
		protected ApiKeyHandlerBase(IOptionsMonitor<ApiKeyOptions> options, ILoggerFactory logger, UrlEncoder encoder)
			: base(options, logger, encoder)
		{
		}
#endif

#if NET6_0 || NET7_0
		///  <summary>
		/// 		Initializes a new instance of the <see cref="ApiKeyHandlerBase"/> type.
		///  </summary>
		///  <param name="options"></param>
		///  <param name="logger"></param>
		///  <param name="encoder"></param>
		///  <param name="systemClock"></param>
		protected ApiKeyHandlerBase(IOptionsMonitor<ApiKeyOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock systemClock)
			: base(options, logger, encoder, systemClock)
		{
		}
#endif

		private string Challenge => $"{this.GetWwwAuthenticateSchemeName()} realm=\"{this.Options.Realm}\", charset=\"UTF-8\", in=\"{this.GetWwwAuthenticateInParameter()}\", key_name=\"{this.Options.KeyName}\"";

		/// <summary>
		///     Get or set <see cref="ApiKeyEvents" />.
		/// </summary>
		protected new ApiKeyEvents Events
		{
			get => (ApiKeyEvents)base.Events;
			set => base.Events = value;
		}

		/// <summary>
		///     Create an instance of <see cref="ApiKeyEvents" />.
		/// </summary>
		/// <returns></returns>
		protected override Task<object> CreateEventsAsync()
		{
			return Task.FromResult<object>(new ApiKeyEvents());
		}

		protected abstract Task<string> ParseApiKeyAsync();

		/// <inheritdoc />
		protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
		{
			if(this.IgnoreAuthenticationIfAllowAnonymous())
			{
				this.Logger.LogDebug("AllowAnonymous found on the endpoint so request was not authenticated.");
				return AuthenticateResult.NoResult();
			}

			string apiKey = string.Empty;
			try
			{
				apiKey = await this.ParseApiKeyAsync().ConfigureAwait(false);
			}
			catch(Exception exception)
			{
				this.Logger.LogError(exception, "Error parsing api key.");
				return AuthenticateResult.Fail("Error parsing api key." + Environment.NewLine + exception.Message);
			}

			if(string.IsNullOrWhiteSpace(apiKey))
			{
				this.Logger.LogInformation("No Api Key found in the request.");
				return AuthenticateResult.NoResult();
			}

			try
			{
				AuthenticateResult validateCredentialsResult = await this.RaiseAndHandleEventValidateKeyAsync(apiKey).ConfigureAwait(false);
				if(validateCredentialsResult != null)
				{
					// If result is set then return it.
					return validateCredentialsResult;
				}

				// Validate using the implementation of IApiKeyProvider.
				IApiKey validatedApiKey = await this.ValidateUsingApiKeyProviderAsync(apiKey).ConfigureAwait(false);
				if(validatedApiKey == null || (!this.Options.ForLegacyIgnoreExtraValidatedApiKeyCheck && !string.Equals(validatedApiKey.Key, apiKey, StringComparison.OrdinalIgnoreCase))
				  )
				{
					this.Logger.LogError($"Invalid API Key provided by {nameof(IApiKeyAuthenticationService)}.");
					return AuthenticateResult.Fail($"Invalid API Key provided by {nameof(IApiKeyAuthenticationService)}.");
				}

				return await this.RaiseAndHandleAuthenticationSucceededAsync(validatedApiKey).ConfigureAwait(false);
			}
			catch(Exception exception)
			{
				ApiKeyAuthenticationFailedContext authenticationFailedContext = new ApiKeyAuthenticationFailedContext(this.Context, this.Scheme, this.Options, exception);
				await this.Events.AuthenticationFailedAsync(authenticationFailedContext).ConfigureAwait(false);

				if(authenticationFailedContext.Result != null)
				{
					return authenticationFailedContext.Result;
				}

				throw;
			}
		}

		/// <inheritdoc />
		protected override async Task HandleForbiddenAsync(AuthenticationProperties properties)
		{
			// Raise handle forbidden event.
			ApiKeyHandleForbiddenContext handleForbiddenContext = new MadEyeMatt.AspNetCore.Authentication.ApiKey.Events.ApiKeyHandleForbiddenContext(this.Context, this.Scheme, this.Options, properties);
			await this.Events.HandleForbiddenAsync(handleForbiddenContext).ConfigureAwait(false);
			if(handleForbiddenContext.IsHandled)
			{
				return;
			}

			await base.HandleForbiddenAsync(properties);
		}

		/// <summary>
		///     Handles the un-authenticated requests.
		///     Returns 401 status code in response.
		///     If <see cref="ApiKeyOptions.SuppressWWWAuthenticateHeader" /> is not set then,
		///     adds 'WWW-Authenticate' response header with KeyName as authentication scheme and 'Realm'
		///     to let the client know which authentication scheme is being used by the system.
		/// </summary>
		/// <param name="properties">
		///     <see cref="AuthenticationProperties" />
		/// </param>
		/// <returns>A Task.</returns>
		protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
		{
			// Raise handle challenge event.
			ApiKeyHandleChallengeContext handleChallengeContext = new ApiKeyHandleChallengeContext(this.Context, this.Scheme, this.Options, properties);
			await this.Events.HandleChallengeAsync(handleChallengeContext).ConfigureAwait(false);
			if(handleChallengeContext.IsHandled)
			{
				return;
			}

			if(!this.Options.SuppressWWWAuthenticateHeader)
			{
				this.Response.Headers[HeaderNames.WWWAuthenticate] = this.Challenge;
			}

			await base.HandleChallengeAsync(properties);
		}

		private async Task<AuthenticateResult> RaiseAndHandleEventValidateKeyAsync(string apiKey)
		{
			ApiKeyValidateKeyContext validateApiContext = new ApiKeyValidateKeyContext(this.Context, this.Scheme, this.Options, apiKey);
			await this.Events.ValidateKeyAsync(validateApiContext).ConfigureAwait(false);

			if(validateApiContext.Result != null)
			{
				return validateApiContext.Result;
			}

			if(validateApiContext.Principal?.Identity != null && validateApiContext.Principal.Identity.IsAuthenticated)
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
			ClaimsPrincipal principal = ApiKeyUtils.BuildClaimsPrincipal(apiKey.OwnerName, this.Scheme.Name, this.ClaimsIssuer, apiKey.Claims);

			// Raise authentication succeeded event.
			ApiKeyAuthenticationSucceededContext authenticationSucceededContext = new ApiKeyAuthenticationSucceededContext(this.Context, this.Scheme, this.Options, principal);
			await this.Events.AuthenticationSucceededAsync(authenticationSucceededContext).ConfigureAwait(false);

			if(authenticationSucceededContext.Result != null)
			{
				return authenticationSucceededContext.Result;
			}

			if(authenticationSucceededContext.Principal?.Identity != null && authenticationSucceededContext.Principal.Identity.IsAuthenticated)
			{
				// If claims principal is set and is authenticated then build a ticket by calling and return success.
				authenticationSucceededContext.Success();
				return authenticationSucceededContext.Result;
			}

			this.Logger.LogError("No authenticated principal set.");
			return AuthenticateResult.Fail("No authenticated principal set.");
		}

		private async Task<IApiKey> ValidateUsingApiKeyProviderAsync(string apiKey)
		{
			IApiKeyAuthenticationService apiKeyAuthenticationService = null;

			// Try to get an instance of the IBasicUserValidationServiceFactory.
			IApiKeyAuthenticationServiceFactory apiKeyProviderFactory = this.Context.RequestServices.GetService<IApiKeyAuthenticationServiceFactory>();

			// Try to get a IApiKeyProvider instance from the factory.
			apiKeyAuthenticationService = apiKeyProviderFactory?.CreateApiKeyAuthenticationService(this.Options.AuthenticationSchemeName);

			if(apiKeyAuthenticationService == null && this.Options.ApiKeyProviderType != null)
			{
				apiKeyAuthenticationService = ActivatorUtilities.GetServiceOrCreateInstance(this.Context.RequestServices, this.Options.ApiKeyProviderType) as IApiKeyAuthenticationService;
			}

			if(apiKeyAuthenticationService == null)
			{
				throw new InvalidOperationException($"Either {nameof(this.Options.Events.OnValidateKey)} delegate on configure options {nameof(this.Options.Events)} should be set or use an extension method with type parameter of type {nameof(IApiKeyAuthenticationService)} or register an implementation of type {nameof(IApiKeyAuthenticationServiceFactory)} in the service collection.");
			}

			try
			{
				return await apiKeyAuthenticationService.AuthenticateAsync(apiKey).ConfigureAwait(false);
			}
			finally
			{
				if(apiKeyAuthenticationService is IDisposable disposableApiKeyProvider)
				{
					disposableApiKeyProvider.Dispose();
				}
			}
		}

		private string GetWwwAuthenticateSchemeName()
		{
			return this.Options.ForLegacyUseKeyNameAsSchemeNameOnWWWAuthenticateHeader
				? this.Options.KeyName
				: this.Scheme.Name;
		}

		private string GetWwwAuthenticateInParameter()
		{
			Type handlerType = this.GetType();

			if(handlerType == typeof(ApiKeyInAuthorizationHeaderHandler))
			{
				return "authorization_header";
			}

			if(handlerType == typeof(ApiKeyInHeaderHandler))
			{
				return "header";
			}

			if(handlerType == typeof(ApiKeyInQueryParamsHandler))
			{
				return "query_params";
			}

			if(handlerType == typeof(ApiKeyInHeaderOrQueryParamsHandler))
			{
				return "header_or_query_params";
			}

			throw new NotImplementedException($"No parameter name defined for {handlerType.FullName}.");
		}

		private bool IgnoreAuthenticationIfAllowAnonymous()
		{
			return this.Options.IgnoreAuthenticationIfAllowAnonymous
				&& this.Context.GetEndpoint()?.Metadata?.GetMetadata<Microsoft.AspNetCore.Authorization.IAllowAnonymous>() != null;
		}
	}
}
