﻿// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.ApiKey
{
	using System.Collections.Generic;
	using System.Security.Claims;

	/// <summary>
	///     API Key Details
	/// </summary>
	public interface IApiKey
	{
		/// <summary>
		///     API Key
		/// </summary>
		string Key { get; }

		/// <summary>
		///     Owner of the API Key. It can be username or any other key owner name.
		/// </summary>
		string OwnerName { get; }

		/// <summary>
		///     Optional list of claims to be sent back with the authentication request.
		/// </summary>
		IReadOnlyCollection<Claim> Claims { get; }
	}
}
