use std::{collections::HashMap, process};

use miette::Diagnostic;
use serde_json::Value;
use thiserror::Error;
use turbopath::{AbsoluteSystemPath, AbsoluteSystemPathBuf};
use turborepo_ui::{cprintln, BOLD, BOLD_GREEN, BOLD_RED, GREY};

use crate::{cli, commands::CommandBase};

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("Failed to read package.json at {path}")]
    FailedToReadPackageJson {
        path: AbsoluteSystemPathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to parse package.json at {path}")]
    FailedToParsePackageJson {
        path: AbsoluteSystemPathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("Failed to find any package.json files")]
    NoPackageJsonFound,
}

struct DependencyVersion {
    version: String,
    locations: Vec<String>,
}

fn find_inconsistencies(
    dep_map: &HashMap<String, DependencyVersion>,
) -> HashMap<String, HashMap<String, Vec<String>>> {
    let mut inconsistencies: HashMap<String, HashMap<String, Vec<String>>> = HashMap::new();

    // Group dependencies by their base name (stripping version suffixes)
    for (full_name, dep_info) in dep_map {
        let base_name = if full_name.contains('@') {
            // This is a versioned entry like "react@16.0.0"
            full_name.split('@').next().unwrap().to_string()
        } else {
            // This is a regular entry
            full_name.clone()
        };

        // Add to the version map for this dependency
        inconsistencies
            .entry(base_name)
            .or_insert_with(HashMap::new)
            .entry(dep_info.version.clone())
            .or_insert_with(Vec::new)
            .extend(dep_info.locations.clone());
    }

    // Filter out dependencies with only one version
    inconsistencies.retain(|_, versions| versions.len() > 1);

    inconsistencies
}

pub async fn run(base: CommandBase) -> Result<i32, cli::Error> {
    let repo_root = &base.repo_root;
    let color_config = base.color_config;

    // Find all package.json files
    let package_json_files = find_package_json_files(repo_root)?;

    if package_json_files.is_empty() {
        return Err(Error::NoPackageJsonFound.into());
    }

    cprintln!(
        color_config,
        BOLD,
        "Checking dependency versions across {} package.json files...",
        package_json_files.len()
    );

    // Collect all dependencies and their versions
    let mut dependencies_map: HashMap<String, HashMap<String, DependencyVersion>> = HashMap::new();

    // Group dependencies into "dependencies" and "devDependencies"
    dependencies_map.insert("dependencies".to_string(), HashMap::new());
    dependencies_map.insert("devDependencies".to_string(), HashMap::new());

    for package_json_path in &package_json_files {
        process_package_json(package_json_path, repo_root, &mut dependencies_map)?;
    }

    // Check for inconsistencies and build report
    let mut has_inconsistencies = false;
    let mut total_inconsistencies = 0;

    for (dep_type, dep_map) in &dependencies_map {
        let inconsistencies = find_inconsistencies(dep_map);

        if !inconsistencies.is_empty() {
            has_inconsistencies = true;
            total_inconsistencies += inconsistencies.len();

            cprintln!(color_config, BOLD, "\nInconsistent {} found:", dep_type);

            for (dep_name, versions) in inconsistencies {
                cprintln!(
                    color_config,
                    BOLD_RED,
                    "  {} has {} different versions:",
                    dep_name,
                    versions.len()
                );

                for (version, locations) in versions {
                    println!("    {} version '{}' in:", GREY.apply_to("→"), version);

                    for location in &locations {
                        println!("      {}", location);
                    }
                }

                println!();
            }
        }
    }

    if has_inconsistencies {
        cprintln!(
            color_config,
            BOLD_RED,
            "\nDependency check failed: {} inconsistent dependencies found.",
            total_inconsistencies
        );
        Ok(1)
    } else {
        cprintln!(
            color_config,
            BOLD_GREEN,
            "\nDependency check passed: no inconsistent versions found."
        );
        Ok(0)
    }
}

fn find_package_json_files(
    repo_root: &AbsoluteSystemPath,
) -> Result<Vec<AbsoluteSystemPathBuf>, Error> {
    let output = process::Command::new("find")
        .arg(repo_root.as_str())
        .arg("-name")
        .arg("package.json")
        .arg("-type")
        .arg("f")
        .arg("-not")
        .arg("-path")
        .arg("*/node_modules/*")
        .output()
        .map_err(|e| Error::FailedToReadPackageJson {
            path: repo_root.to_owned(),
            source: e,
        })?;

    if !output.status.success() {
        return Err(Error::NoPackageJsonFound);
    }

    let files_str = String::from_utf8_lossy(&output.stdout);
    let files: Vec<AbsoluteSystemPathBuf> = files_str
        .lines()
        .map(|line| AbsoluteSystemPathBuf::new(line.trim()).unwrap())
        .collect();

    Ok(files)
}

fn process_package_json(
    package_json_path: &AbsoluteSystemPath,
    repo_root: &AbsoluteSystemPath,
    dependencies_map: &mut HashMap<String, HashMap<String, DependencyVersion>>,
) -> Result<(), Error> {
    let package_json_content =
        package_json_path
            .read_to_string()
            .map_err(|e| Error::FailedToReadPackageJson {
                path: package_json_path.to_owned(),
                source: e,
            })?;

    let package_json: Value = serde_json::from_str(&package_json_content).map_err(|e| {
        Error::FailedToParsePackageJson {
            path: package_json_path.to_owned(),
            source: e,
        }
    })?;

    let relative_path = package_json_path
        .as_path()
        .strip_prefix(repo_root.as_path())
        .unwrap_or_else(|_| package_json_path.as_path())
        .to_string();

    let package_name = package_json
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("unnamed-package");

    let location = format!("{} ({})", package_name, relative_path);

    // Process both dependency types
    process_dependency_type("dependencies", &package_json, &location, dependencies_map);
    process_dependency_type(
        "devDependencies",
        &package_json,
        &location,
        dependencies_map,
    );

    Ok(())
}

fn process_dependency_type(
    dep_type: &str,
    package_json: &Value,
    location: &str,
    dependencies_map: &mut HashMap<String, HashMap<String, DependencyVersion>>,
) {
    if let Some(deps) = package_json.get(dep_type).and_then(|v| v.as_object()) {
        let dep_map = dependencies_map.get_mut(dep_type).unwrap();

        for (dep_name, version_value) in deps {
            if let Some(version) = version_value.as_str() {
                // Check if we already have this dependency with this version
                let version_exists = dep_map
                    .get(dep_name)
                    .map_or(false, |entry| entry.version == version);

                if version_exists {
                    // If this version already exists, just add the location
                    if let Some(entry) = dep_map.get_mut(dep_name) {
                        entry.locations.push(location.to_string());
                    }
                } else {
                    // This is a new dependency or a new version of an existing dependency
                    // We need to build a HashMap keyed by version
                    let mut dep_versions = HashMap::new();

                    // If the dependency already exists with different versions,
                    // we need to handle the existing versions
                    if let Some(existing_entry) = dep_map.remove(dep_name) {
                        // Insert the existing version
                        dep_versions
                            .insert(existing_entry.version.clone(), existing_entry.locations);
                    }

                    // Now add the new version
                    let mut locations = Vec::new();
                    locations.push(location.to_string());
                    dep_versions.insert(version.to_string(), locations);

                    // If this is the first time we've seen a version,
                    // create a new entry for the dependency name
                    // Otherwise, add this version to the existing versions
                    if dep_versions.len() == 1 {
                        // Only one version, use the simple structure
                        let (version, locations) = dep_versions.into_iter().next().unwrap();
                        dep_map.insert(dep_name.clone(), DependencyVersion { version, locations });
                    } else {
                        // Multiple versions, create a "fake" entry that will be caught
                        // as an inconsistency. We'll use the most recent version
                        // (which is the one we just added)
                        let new_locations = dep_versions.get(version).unwrap().clone();
                        dep_map.insert(
                            dep_name.clone(),
                            DependencyVersion {
                                version: version.to_string(),
                                locations: new_locations,
                            },
                        );

                        // We add entries for all other versions too
                        for (ver, locs) in dep_versions {
                            if ver != version {
                                let name_with_ver = format!("{}@{}", dep_name, ver);
                                dep_map.insert(
                                    name_with_ver,
                                    DependencyVersion {
                                        version: ver,
                                        locations: locs,
                                    },
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}
