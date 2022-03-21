#!/bin/bash
set -e

read -p "WARNING: This is a proof of concept script and some side affects my adversely affect your system. Continue (y/n)? " -n 1 -r
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    exit 1
fi

# 0. Testing setup commands
## Helper function for testing only
download_deb() {
local base_path="$1"
local version="$2"
echo "Downloading version ${version} to \"${base_path}\""
for arch in "i386" "amd64" "arm" "arm64"; do
	filename="teleport_${version}_${arch}.deb"
	full_filepath="${base_path}/${version}/${arch}/${filename}"
	if test -f "$full_filepath"; then
		echo "\"$full_filepath\" exists, skipping"
		continue
	fi

	url="https://get.gravitational.com/${filename}"
	mkdir -p "${base_path}/${version}/${arch}"
	echo -n "Downloading ${url}... "
	wget -q -O "$full_filepath" "$url"
	echo "done"
done
}

## Set some config vars
download_versions=("8.1.5" "8.0.7" "7.3.13" "6.2.26")
artifact_version="8.2.0"
deb_path="/debs"
artifacts_path="/artifacts"
declare -A supported_os_versions=(
	["ubuntu"]="groovy focal eoan disco cosmic bionic"
	["debian"]="bullseye buster stretch"
)

## Do cleanup
rm -rfv "${HOME}/.aptly"
#rm -rf "$deb_path"
#rm -rf "$artifacts_path"
rm -rf "${HOME}/.gnupg"

## Create a GPG signing key
export GPG_TTY=$(tty)
gpg1 --batch --gen-key <<EOF
Key-Type: 1
Key-Length: 2048
Subkey-Type: 1
Subkey-Length: 2048
Name-Real: Test Signingkey
Name-Email: fred.heinecke@goteleport.com
Expire-Date: 0
EOF

# 1. Download all debs
## Normally this would be done via `s3 copy`, but for testing purposes we're downloading a handful of versions from the testing page
echo "Downloading pre-existing debs..."
for version in ${download_versions[@]}; do
	download_deb "$deb_path" "$version"
done
# 2. Install aptly
echo "Installing aptly..."
## Note: Aptly does not play nice with gpgv2, so we specify v1 here
apt install aptly gnupg1 -y
# 3. Copy built debs over
## Normally this would be copied from a build directory in the pipeline, but for testing we're just going to pull a version from the downloads page
download_deb "$artifacts_path" "${artifact_version}"

echo "Copying over built deb artifacts..."
cp -rv "$artifacts_path/"* "$deb_path"
found_major_versions=(`ls "$deb_path" | cut -c 1 | uniq`)

for os in ${!supported_os_versions[@]}; do
	for os_version in ${supported_os_versions[$os]}; do
		for major_version in ${found_major_versions[@]}; do
# 4. Create repo w/ aptly
			echo "Creating ${os}/${os_version} repo for Teleport v${major_version}..."
			repo_name="${os}-${os_version}-v${major_version}"
			# Note: I'm note sure if we fully conform to DFSG (https://www.debian.org/social_contract#guidelines) so I'm listing the component as `non-free` for now
			aptly repo create -distribution="$os_version" -component="non-free/stable/v${major_version}" "$repo_name"
			echo "Created repo \"${repo_name}\""	
# 5. Import downloaded debs
			echo "Importing artifacts for ${major_version}..."
			minor_version_paths=(`ls -d "${deb_path}/${major_version}"*`)
			for minor_version_path in ${minor_version_paths[@]}; do
				echo "Adding \"${minor_version_path}\" to ${repo_name}... "
				aptly repo add "$repo_name" "$minor_version_path"
				echo "Done"
			done
		done
# 6. Publish repo
			created_repos=(`aptly repo list -raw | grep "${os}-${os_version}"`)
			components=`printf ",%.0s" $(seq $((${#created_repos[@]} - 1)))`
			echo "Publishing repos ${created_repos[@]}..."
			aptly publish repo -component="${components}" ${created_repos[@]} "${os}"
	done
done

# 7. Sync folder to s3
## Normally this would be done by adding a parameter to the `aptly publish repo`, or via `s3 sync` step but I left it out for the proof of concept
