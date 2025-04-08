use std::{collections::HashMap, process};

use glob::Pattern;
use miette::Diagnostic;
use serde_json::Value;
use thiserror::Error;
use turbopath::{AbsoluteSystemPath, AbsoluteSystemPathBuf};
use turborepo_ui::{cprintln, BOLD, BOLD_GREEN, BOLD_RED, CYAN, GREY};

use crate::{
    cli,
    commands::CommandBase,
    turbo_json::{DependencyConfig, RawTurboJson},
};

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

    #[error("Failed to read turbo.json at {path}")]
    FailedToReadTurboJson {
        path: AbsoluteSystemPathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to parse turbo.json at {path}")]
    FailedToParseTurboJson {
        path: AbsoluteSystemPathBuf,
        #[source]
        source: serde_json::Error,
    },
}

#[derive(Debug)]
struct DependencyVersion {
    version: String,
    locations: Vec<String>,
}

fn find_inconsistencies(
    dep_map: &HashMap<String, DependencyVersion>,
    turbo_config: Option<&RawTurboJson>,
) -> HashMap<String, HashMap<String, Vec<String>>> {
    let mut result: HashMap<String, HashMap<String, Vec<String>>> = HashMap::new();

    // First, group all dependencies by their base name (without version suffix)
    for (full_name, dep_info) in dep_map {
        // Extract base name from keys like "package@version" or just use the original
        // name, handling scoped packages properly
        let base_name = if full_name.starts_with('@') {
            // This is a scoped package like "@babel/core" or "@types/react"
            // If it also has @version, extract just the package name part
            if let Some(version_idx) = full_name[1..].find('@') {
                &full_name[0..=version_idx]
            } else {
                // It's a scoped package without version suffix
                full_name.as_str()
            }
        } else if full_name.contains('@') {
            // This is a versioned entry like "react@16.0.0"
            full_name.split('@').next().unwrap()
        } else {
            // This is a regular entry
            full_name.as_str()
        };

        // Add this version to the base dependency's version map
        result
            .entry(base_name.to_string())
            .or_insert_with(HashMap::new)
            .entry(dep_info.version.clone())
            .or_insert_with(Vec::new)
            .extend(dep_info.locations.clone());
    }

    // Filter out dependencies with only one version, unless it's pinned to a
    // specific version
    result.retain(|name, versions| {
        // Check if this dependency has a rule in the turbo.json config
        if let Some(config) = turbo_config.and_then(|c| c.dependencies.as_ref()) {
            if let Some(dep_config) = config.get(name) {
                // Check if the rule should be applied by matching package patterns
                if !dep_config.packages.is_empty()
                    && versions.values().any(|locations| {
                        locations.iter().any(|location| {
                            matches_any_package_pattern(location, &dep_config.packages)
                        })
                    })
                {
                    // Rule applies to at least one package
                    // Due to validation, we know only one of ignore or pin_to_version is set
                    if dep_config.ignore {
                        // If dependency is ignored, don't include in inconsistencies
                        return false;
                    }
                    if let Some(pin_version) = &dep_config.pin_to_version {
                        // Check if all versions match the pinned version
                        return versions.keys().any(|v| v != pin_version);
                    }
                }
            }
        }

        // Default behavior: only show if there are multiple versions
        versions.len() > 1
    });

    result
}

// Helper function to check if a location matches any of the package patterns
fn matches_any_package_pattern(location: &str, patterns: &[String]) -> bool {
    // Extract the package name from the location string (format: "package-name
    // (path/to/package)")
    let package_name = if let Some(paren_idx) = location.find(" (") {
        &location[0..paren_idx]
    } else {
        location // Fall back to full string if format is unexpected
    };

    // Check if any pattern matches
    patterns.iter().any(|pattern| {
        // Special case: "**" or "*" means all packages
        if pattern == "**" || pattern == "*" {
            return true;
        }

        // Use glob pattern matching
        if let Ok(glob_pattern) = Pattern::new(pattern) {
            glob_pattern.matches(package_name)
        } else {
            // If pattern is invalid, just do an exact match
            pattern == package_name
        }
    })
}

pub async fn run(base: CommandBase) -> Result<i32, cli::Error> {
    let repo_root = &base.repo_root;
    let color_config = base.color_config;

    // Find all package.json files
    let package_json_files = find_package_json_files(repo_root)?;

    if package_json_files.is_empty() {
        return Err(Error::NoPackageJsonFound.into());
    }

    // Try to load the root turbo.json if it exists
    let turbo_config = load_turbo_json(repo_root).ok();

    cprintln!(
        color_config,
        BOLD,
        "Checking dependency versions across {} package.json files...",
        package_json_files.len()
    );

    // Print dependency configuration information if available
    if let Some(config) = &turbo_config {
        if let Some(dependencies) = &config.dependencies {
            if !dependencies.is_empty() {
                cprintln!(color_config, BOLD, "\nDependency rules from turbo.json:");

                let mut has_active_rules = false;

                for (dep_name, dep_config) in dependencies {
                    if dep_config.packages.is_empty() {
                        cprintln!(
                            color_config,
                            GREY,
                            "  {} - NO EFFECT (no packages specified)",
                            dep_name
                        );
                        continue;
                    }

                    has_active_rules = true;

                    if dep_config.ignore {
                        cprintln!(
                            color_config,
                            CYAN,
                            "  {} - IGNORED for patterns: {}",
                            dep_name,
                            dep_config.packages.join(", ")
                        );
                    } else if let Some(version) = &dep_config.pin_to_version {
                        cprintln!(
                            color_config,
                            CYAN,
                            "  {} - PINNED to version {} for patterns: {}",
                            dep_name,
                            version,
                            dep_config.packages.join(", ")
                        );
                    }
                }

                if !has_active_rules {
                    cprintln!(
                        color_config,
                        BOLD_RED,
                        "  Warning: No active dependency rules found in turbo.json - check your \
                         configuration"
                    );
                }

                println!();
            }
        }
    }

    // Collect all dependencies and their versions - we use a single map for all
    // dependency types
    let mut all_dependencies_map: HashMap<String, DependencyVersion> = HashMap::new();

    for package_json_path in &package_json_files {
        process_package_json(package_json_path, repo_root, &mut all_dependencies_map)?;
    }

    // Check for pinned dependencies that need enforcement
    if let Some(config) = &turbo_config {
        if let Some(dependencies) = &config.dependencies {
            enforce_pinned_dependencies(dependencies, &mut all_dependencies_map, color_config);
        }
    }

    // Check for inconsistencies and build report
    let mut total_inconsistencies = 0;

    let inconsistencies = find_inconsistencies(&all_dependencies_map, turbo_config.as_ref());

    if !inconsistencies.is_empty() {
        total_inconsistencies += inconsistencies.len() as u32;

        for (dep_name, versions) in inconsistencies {
            cprintln!(
                color_config,
                CYAN,
                "  {} has {} different versions in the workspace.",
                dep_name,
                versions.len()
            );

            for (version, locations) in versions {
                println!("{} version '{}' in:", "→", BOLD_RED.apply_to(version));

                for location in &locations {
                    cprintln!(color_config, GREY, "  {}", location);
                }
            }

            println!();
        }
    }

    if total_inconsistencies > 1 {
        cprintln!(
            color_config,
            BOLD_RED,
            "{} unsynced dependencies found.",
            total_inconsistencies
        );

        Ok(1)
    } else if total_inconsistencies == 1 {
        cprintln!(
            color_config,
            BOLD_RED,
            "{} unsynced dependency found.",
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

// Load the turbo.json config file directly using the crate's built-in
// functionality
fn load_turbo_json(repo_root: &AbsoluteSystemPath) -> Result<RawTurboJson, Error> {
    let turbo_json_path = repo_root.join_component("turbo.json");

    if !turbo_json_path.exists() {
        return Err(Error::FailedToReadTurboJson {
            path: turbo_json_path,
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "turbo.json not found"),
        });
    }

    let turbo_json_content =
        turbo_json_path
            .read_to_string()
            .map_err(|e| Error::FailedToReadTurboJson {
                path: turbo_json_path.clone(),
                source: e,
            })?;

    // Use the built-in parser from RawTurboJson
    match RawTurboJson::parse(&turbo_json_content, turbo_json_path.as_str()) {
        Ok(turbo_json) => Ok(turbo_json),
        Err(err) => {
            // Create a simple JSON parsing error with the error message
            let json_err =
                serde_json::from_str::<serde_json::Value>(&format!("{{\"error\": \"{}\"", err))
                    .unwrap_err();
            Err(Error::FailedToParseTurboJson {
                path: turbo_json_path,
                source: json_err,
            })
        }
    }
}

// Enforce pinned dependency versions
fn enforce_pinned_dependencies(
    dependencies: &HashMap<String, DependencyConfig>,
    all_dependencies_map: &mut HashMap<String, DependencyVersion>,
    color_config: turborepo_ui::ColorConfig,
) {
    for (dep_name, config) in dependencies {
        // Due to validation, we know only one of ignore or pin_to_version is set
        if let Some(pinned_version) = &config.pin_to_version {
            // Skip if no packages are specified
            if config.packages.is_empty() {
                continue;
            }

            cprintln!(
                color_config,
                BOLD,
                "Enforcing pinned version {} for {}",
                pinned_version,
                dep_name
            );

            // Create a map of keys to modify and their new versions
            let mut updates = Vec::new();

            // Find matching dependencies
            for (key, dep_info) in all_dependencies_map.iter() {
                // Check if this is the dependency we're looking for
                let base_name = extract_base_name(key);

                if base_name == dep_name {
                    // Check if any location matches our package patterns
                    let should_enforce = dep_info
                        .locations
                        .iter()
                        .any(|location| matches_any_package_pattern(location, &config.packages));

                    if should_enforce {
                        updates.push((key.clone(), dep_info.locations.clone()));
                    }
                }
            }

            // Apply updates
            for (key, locations) in updates {
                // Replace with the pinned version
                all_dependencies_map.insert(
                    key,
                    DependencyVersion {
                        version: pinned_version.clone(),
                        locations,
                    },
                );
            }
        }
    }
}

// Helper to extract the base name from a dependency key
fn extract_base_name(full_name: &str) -> &str {
    if full_name.starts_with('@') {
        // This is a scoped package like "@babel/core" or "@types/react"
        // If it also has @version, extract just the package name part
        if let Some(version_idx) = full_name[1..].find('@') {
            &full_name[0..=version_idx]
        } else {
            // It's a scoped package without version suffix
            full_name
        }
    } else if full_name.contains('@') {
        // This is a versioned entry like "react@16.0.0"
        full_name.split('@').next().unwrap()
    } else {
        // This is a regular entry
        full_name
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
    all_dependencies_map: &mut HashMap<String, DependencyVersion>,
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
    process_dependency_type(
        "dependencies",
        &package_json,
        &location,
        all_dependencies_map,
    );
    process_dependency_type(
        "devDependencies",
        &package_json,
        &location,
        all_dependencies_map,
    );

    Ok(())
}

fn process_dependency_type(
    dep_type: &str,
    package_json: &Value,
    location: &str,
    all_dependencies_map: &mut HashMap<String, DependencyVersion>,
) {
    if let Some(deps) = package_json.get(dep_type).and_then(|v| v.as_object()) {
        for (dep_name, version_value) in deps {
            if let Some(version) = version_value.as_str() {
                // Check if we already have this dependency
                if let Some(entry) = all_dependencies_map.get(&dep_name.clone()) {
                    if entry.version == version {
                        // Same version, just add the location
                        let mut locations = entry.locations.clone();
                        locations.push(location.to_string());

                        // Update with the new locations
                        all_dependencies_map.insert(
                            dep_name.clone(),
                            DependencyVersion {
                                version: version.to_string(),
                                locations,
                            },
                        );
                    } else {
                        // Different version - create new versioned entries in the result directly
                        // We DON'T want to modify the key names here

                        // We need to preserve both versions with their locations
                        // Create a versioned map in the find_inconsistencies function

                        // For now, just add this version to the result with a unique key
                        // that preserves the package name but includes version info
                        let versioned_key = format!("{}@{}", dep_name, version);

                        all_dependencies_map.insert(
                            versioned_key,
                            DependencyVersion {
                                version: version.to_string(),
                                locations: vec![location.to_string()],
                            },
                        );
                    }
                } else {
                    // New dependency, just add it with the clean name
                    all_dependencies_map.insert(
                        dep_name.clone(),
                        DependencyVersion {
                            version: version.to_string(),
                            locations: vec![location.to_string()],
                        },
                    );
                }
            }
        }
    }
}
