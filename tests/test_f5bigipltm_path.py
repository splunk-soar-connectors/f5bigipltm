# Copyright (c) 2026 Splunk Inc.
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
import pytest

from f5bigipltm_path import quote_path_component


@pytest.mark.parametrize("value", ["", ".", ".."])
def test_quote_path_component_rejects_empty_and_dot_segments(value):
    with pytest.raises(ValueError, match="cannot be empty or dot segments"):
        quote_path_component(value)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("../../auth/user", "..%2F..%2Fauth%2Fuser"),
        ("%2e%2e%2fauth", "%252e%252e%252fauth"),
        ("node?x=1#fragment", "node%3Fx%3D1%23fragment"),
        ("~Common~node", "%7ECommon%7Enode"),
    ],
)
def test_quote_path_component_encodes_structural_characters(value, expected):
    assert quote_path_component(value) == expected
