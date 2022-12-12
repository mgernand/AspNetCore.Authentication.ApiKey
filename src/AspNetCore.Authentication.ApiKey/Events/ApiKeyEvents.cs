// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.ApiKey.Events
{
	using System;
	using System.Threading.Tasks;

	/// <summary>
	///     ApiKey Events.
	/// </summary>
	public class ApiKeyEvents
	{
		/// <summary>
		///     A delegate assigned to this property will be invoked just before validating api key.
		/// </summary>
		/// <remarks>
		///     You must provide a delegate for this property for authentication to occur.
		///     In your delegate you should either call context.ValidationSucceeded() which will handle construction of
		///     authentication principal which will be assigned the context.Principal property and call context.Success(),
		///     or construct an authentication principal &amp; attach it to the context.Principal property and finally call
		///     context.Success() method.
		///     If only context.Principal property set without calling context.Success() method then, Success() method is
		///     automatically called.
		/// </remarks>
		public Func<ApiKeyValidateKeyContext, Task> OnValidateKey { get; set; }

		/// <summary>
		///     A delegate assigned to this property will be invoked when the authentication succeeds. It will not be called if
		///     <see cref="OnValidateKey" /> delegate is assigned.
		///     It can be used for adding claims, headers, etc to the response.
		/// </summary>
		/// <remarks>
		///     Only use this if you know what you are doing.
		/// </remarks>
		public Func<ApiKeyAuthenticationSucceededContext, Task> OnAuthenticationSucceeded { get; set; }

		/// <summary>
		///     A delegate assigned to this property will be invoked when the authentication fails.
		/// </summary>
		public Func<ApiKeyAuthenticationFailedContext, Task> OnAuthenticationFailed { get; set; }

		/// <summary>
		///     A delegate assigned to this property will be invoked before a challenge is sent back to the caller when handling
		///     unauthorized response.
		/// </summary>
		/// <remarks>
		///     Only use this if you know what you are doing and if you want to use custom implementation.
		///     Set the delegate to deal with 401 challenge concerns, if an authentication scheme in question
		///     deals an authentication interaction as part of it's request flow. (like adding a response header, or
		///     changing the 401 result to 302 of a login page or external sign-in location.)
		///     Call context.Handled() at the end so that any default logic for this challenge will be skipped.
		/// </remarks>
		public Func<ApiKeyHandleChallengeContext, Task> OnHandleChallenge { get; set; }

		/// <summary>
		///     A delegate assigned to this property will be invoked if Authorization fails and results in a Forbidden response.
		/// </summary>
		/// <remarks>
		///     Only use this if you know what you are doing and if you want to use custom implementation.
		///     Set the delegate to handle Forbid.
		///     Call context.Handled() at the end so that any default logic will be skipped.
		/// </remarks>
		public Func<ApiKeyHandleForbiddenContext, Task> OnHandleForbidden { get; set; }


		/// <summary>
		///     Invoked when validating api key.
		/// </summary>
		/// <param name="context"></param>
		/// <returns>A Task.</returns>
		public Task ValidateKeyAsync(ApiKeyValidateKeyContext context)
		{
			return this.OnValidateKey == null ? Task.CompletedTask : this.OnValidateKey(context);
		}

		/// <summary>
		///     Invoked when the authentication succeeds.
		/// </summary>
		/// <param name="context"></param>
		/// <returns>A Task.</returns>
		public Task AuthenticationSucceededAsync(ApiKeyAuthenticationSucceededContext context)
		{
			return this.OnAuthenticationSucceeded == null ? Task.CompletedTask : this.OnAuthenticationSucceeded(context);
		}

		/// <summary>
		///     Invoked when the authentication fails.
		/// </summary>
		/// <param name="context"></param>
		/// <returns>A Task.</returns>
		public Task AuthenticationFailedAsync(ApiKeyAuthenticationFailedContext context)
		{
			return this.OnAuthenticationFailed == null ? Task.CompletedTask : this.OnAuthenticationFailed(context);
		}

		/// <summary>
		///     Invoked before a challenge is sent back to the caller when handling unauthorized response.
		/// </summary>
		/// <remarks>
		///     Override this method to deal with 401 challenge concerns, if an authentication scheme in question
		///     deals an authentication interaction as part of it's request flow. (like adding a response header, or
		///     changing the 401 result to 302 of a login page or external sign-in location.)
		///     Call context.Handled() at the end so that any default logic for this challenge will be skipped.
		/// </remarks>
		/// <param name="context"></param>
		/// <returns>A Task.</returns>
		public Task HandleChallengeAsync(ApiKeyHandleChallengeContext context)
		{
			return this.OnHandleChallenge == null ? Task.CompletedTask : this.OnHandleChallenge(context);
		}

		/// <summary>
		///     Invoked if Authorization fails and results in a Forbidden response.
		/// </summary>
		/// <remarks>
		///     Override this method to handle Forbid.
		///     Call context.Handled() at the end so that any default logic will be skipped.
		/// </remarks>
		/// <param name="context"></param>
		/// <returns>A Task.</returns>
		public Task HandleForbiddenAsync(ApiKeyHandleForbiddenContext context)
		{
			return this.OnHandleForbidden == null ? Task.CompletedTask : this.OnHandleForbidden(context);
		}
	}
}
