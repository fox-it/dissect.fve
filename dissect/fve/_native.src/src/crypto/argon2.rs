use std::str::FromStr;

use pyo3::{prelude::*, types::PyBytes};

/// Hash ``password`` and return a ``raw`` hash.
///
/// This function automatically uses the default Argon2 version.
///
/// Args:
///     secret: Secret to hash.
///     salt: A salt. Should be random and different for each secret.
///     time_cost: Defines the amount of computation realized and therefore the execution time, given in number of iterations.
///     memory_cost: Defines the memory usage, given in kibibytes.
///     parallelism: Defines the number of parallel threads (*changes* the resulting hash value).
///     hash_len: Length of the hash in bytes.
///     type: Which Argon2 variant to use.
///
/// Returns:
///     An raw Argon2 hash.
///
#[pyfunction]
#[pyo3(signature = (secret, salt, time_cost, memory_cost, parallelism, hash_len, r#type))]
fn hash_secret_raw(
    py: Python<'_>,
    secret: Vec<u8>,
    salt: Vec<u8>,
    time_cost: u32,
    memory_cost: u32,
    parallelism: u32,
    hash_len: usize,
    r#type: String,
) -> PyResult<Bound<'_, PyBytes>> {
    let mut output = vec![0u8; hash_len];

    argon2::Argon2::new(
        argon2::Algorithm::from_str(r#type.as_str())
            .map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("Invalid Argon2 type"))?,
        argon2::Version::default(),
        argon2::Params::new(memory_cost, time_cost, parallelism, Some(hash_len as usize)).map_err(
            |_| PyErr::new::<pyo3::exceptions::PyValueError, _>("Invalid parameters for Argon2"),
        )?,
    )
    .hash_password_into(&secret, &salt, &mut output)
    .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Hashing failed: {e}")))?;

    Ok(PyBytes::new(py, &output).into())
}

pub fn create_submodule(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let submodule = PyModule::new(m.py(), "argon2")?;
    submodule.add_function(wrap_pyfunction!(hash_secret_raw, m)?)?;
    m.add_submodule(&submodule)
}
