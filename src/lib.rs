/*******************************************************************************
*   (c) 2018, 2019 ZondaX GmbH
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
//! Provider for Ledger Tendermint validator app
//#![deny(warnings, trivial_casts, trivial_numeric_casts)]
//#![deny(unused_import_braces, unused_qualifications)]
//#![deny(missing_docs)]
#![doc(
html_logo_url = "https://raw.githubusercontent.com/tendermint/signatory/master/img/signatory-rustacean.png",
html_root_url = "https://docs.rs/ledger-tendermint/0.4.0"
)]

#[macro_use]
extern crate quick_error;

#[cfg(test)]
#[macro_use]
extern crate matches;

#[cfg(test)]
extern crate sha2;

#[cfg(test)]
extern crate ed25519_dalek;

#[cfg(test)]
#[macro_use]
extern crate lazy_static;

pub mod ledgertm;
pub mod signer;
