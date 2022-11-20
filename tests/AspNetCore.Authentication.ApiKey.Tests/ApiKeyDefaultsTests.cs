// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests
{
    using Xunit;

    public class ApiKeyDefaultsTests
    {
        [Fact]
        public void AuthenticationSchemeValueTest()
        {
            Assert.Equal("ApiKey", ApiKeyDefaults.AuthenticationScheme);
        }
    }
}
