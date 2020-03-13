# Copyright 2018 Centrify Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

param(
[string]$Tenant="devdog.centrify.com",
[string]$Location
)

#Import-Module .\Centrify.Authenticate.psm1 -PassThru 3>$null 4>$null -force
Import-Module .\Centrify.Authenticate.psm1 3>$null 4>$null -force

Centrify-Authenticate -Tenant $Tenant $Location
