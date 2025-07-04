#!/bin/bash

#  Copyright 2021-2023 eismann@5H+yXYkQHMnwtQDzJB8thVYAAIs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

# Some lines were taken from the script 1fichier.sh by SoupeAuLait@Rindexxx


checkTor() {
	local torPort=
	for port in 9050 9150 ; do
		echo "" 2>/dev/null > /dev/tcp/127.0.0.1/${port}
		if [ "$?" = "0" ] ; then
			torPort=${port}
		fi
	done
	echo ${torPort}
}


tcurl(){
	curl --proxy "socks5h://${torUser}:${torPassword}@127.0.0.1:${torPort}" --connect-timeout 15 --user-agent "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0" --header "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" --header "Accept-Language: en-US,en;q=0.5" --header "Accept-Encoding: gzip, deflate, br" --compressed "$@"
}


failedDownload() {
	local baseDir=${1}
	local url=${2}
	echo "${url}" >> "${baseDir}/failed.txt"
}


removeTempDir() {
	local tempDir=${1}
	rm -r "${tempDir}"
}


removeCookies() {
	local cookieFile=${1}
	rm -f "${cookieFile}"
}


cancelDownload() {
	echo "Download cancelled."
	removeTempDir "${lastTempDir}"
	exit 1
}


downloadFile() {
	trap cancelDownload SIGINT SIGTERM

	local url=${1}
	echo "Processing \"${url}\""...
	echo -n "Search for a circuit without wait time..."

	local baseDir=$(pwd)
	local tempDir=${baseDir}/$(mktemp --directory "tmp.XXX")
	lastTempDir=${tempDir}

	local filenameRegEx='<td class="normal"><span style="font-weight:bold">([^<]+)</span>.*<span style="font-size:0.9em;font-style:italic">([^<]+)</span>'
	local maxCount=500
	local count=0
	local slotFound="false"
	local alreadyDownloaded="false"
	while [ ${count} -le ${maxCount} ] ; do
		count=$(( ${count} + 1 ))
		echo -n "."

		local cookies=$(mktemp --tmpdir="${tempDir}" "cookies.XXX")
		torUser="user-${RANDOM}"
		torPassword="password-${RANDOM}"

		local downloadPage=$(tcurl --insecure --cookie-jar "${cookies}" --silent --show-error "${url}")
		if [[ "${downloadPage}" =~ ${filenameRegEx} ]] ; then
			echo
			local filename=${BASH_REMATCH[1]}
			#New code
			local size=${BASH_REMATCH[2]}
			if [ ${count} -eq 1 ] ; then
				echo "Filename: ${filename}"
				echo "Size: ${size}"
			fi
			local size_value=$(echo "$size" | sed -E 's/^([0-9.]+) .+$/\1/')
			local size_unit=$(echo "$size" | sed -E 's/^[0-9.]+ ([KMGTkmgt])o?b?O?B?$/\1/' | tr '[:lower:]' '[:upper:]')
			local multiplier=1
			case "$size_unit" in
				K) multiplier=$((1024)) ;;
				M) multiplier=$((1024**2)) ;;
				G) multiplier=$((1024**3)) ;;
				T) multiplier=$((1024**4)) ;;
				*) echo "Unsupported or missing unit: '$size_unit'" >&2; exit 1 ;;
			esac
			local expected_size_bytes=$(awk -v val="$size_value" -v mul="$multiplier" 'BEGIN { printf "%.0f", val * mul }')
			
			if [ -e "${baseDir}/${filename}" ] ; then
				alreadyDownloaded="true"
				break
			fi
		fi

		grep -E -q '<span style="color:red">Warning !</span>|<span style="color:red">Attention !</span>' <<< "${downloadPage}"
		if [ ! "$?" = "0" ] ; then
			local checkSlot=$(perl -nle'print $& while m{name="adz" value="\K[^"]+}g' <<< "${downloadPage}")
			if [ ${checkSlot} ] ; then
				echo "Found. Start downloading..."
				slotFound="true"
				break
			else
				removeCookies "${cookies}"
			fi
		else
			removeCookies "${cookies}"
		fi
	done

	if [ "${alreadyDownloaded}" = "true" ] || [ "${slotFound}" = "false" ] ; then
		if [ "${alreadyDownloaded}" = "true" ] ; then
			echo "Already downloaded. Skipping."
		elif [ "${slotFound}" = "false" ] ; then
			echo "Unable to get a circuit without wait time after ${maxCount} tries."
			failedDownload "${baseDir}" "${url}"
		fi
		removeTempDir "${tempDir}"
		return
	fi

	local downloadLinkPage=$(tcurl --insecure --location --cookie "${cookies}" --cookie-jar "${cookies}" --silent --show-error --form "submit=Download" --form "adz=${get_me}" "${url}")
	local downloadLink=$(echo "${downloadLinkPage}" | grep --after-context=2 '<div style="width:600px;height:80px;margin:auto;text-align:center;vertical-align:middle">' | perl -nle'print $& while m{<a href="\K[^"]+}g')
	if [ "${downloadLink}" ] ; then
		tcurl --insecure --cookie "${cookies}" --referer "${url}" --output "${tempDir}/${filename}" "${downloadLink}" --remote-header-name --remote-name
		if [ "$?" = "0" ] ; then
			removeCookies "${cookies}"
			if [ -e "${tempDir}/${filename}" ] ; then
				local actual_size_bytes=$(stat -c %s "${tempDir}/${filename}")
				local lower_bound=$(awk -v e="$expected_size_bytes" 'BEGIN { printf "%.0f", e * 0.95 }')
				if (( actual_size_bytes >= lower_bound )); then
					mv "${tempDir}/${filename}" "${baseDir}/"
				else
					echo "Download failed. Sizes don't match."
					failedDownload "${baseDir}" "${url}"
				fi
			else
				echo "Download failed."
				failedDownload "${baseDir}" "${url}"
			fi
		else
			failedDownload "${baseDir}" "${url}"
		fi
	else
		echo "Unable to extract download-link."
		failedDownload "${baseDir}" "${url}"
	fi
	removeTempDir "${tempDir}"

	trap - SIGINT SIGTERM
}


if [ "$#" -ne 1 ] ; then
	echo "Usage:"
	echo "${0} File-With-URLs"
	echo "or"
	echo "${0} URL"
	exit 1
fi

torPort=$(checkTor)
if [ "${torPort}" = "" ] ; then
	echo "Tor is not running!"
	exit 1
fi
echo "Tor is listening on port ${torPort}"

lastTempDir=
downloadSource=${1}
if [[ "${downloadSource}" =~ "1fichier.com" ]] ; then
	downloadFile "${downloadSource}"
else
	if [ ! -f "${downloadSource}" ] ; then
		echo "Unable to read file \"${downloadSource}\"!"
		exit 1
	fi
	while IFS= read -r line
	do
		downloadFile "${line}"
	done < "${downloadSource}"
fi
