#!/usr/bin/env bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

PACKAGE_MISSING_EXIT_CODE=5

exit_failure() {
    echo "ERROR: $1"
    # If python3 is not installed and OS is Red hat provide a link for Python3 installation guide at RHEL official documentation
    if [ -f "/etc/redhat-release" ] && [[ "Python3 is not installed" == *"$1"* ]]; then
        echo "Please advise Red Hat official documentation on how to install Python3 on RHEL machine:"
        echo "https://developers.redhat.com/blog/2018/08/13/install-python3-rhel/"
    fi
    exit
}

export PYTHONUSERBASE="$DIR"/mde_tools/.deps
export PATH=$PYTHONUSERBASE/bin:$PATH

PYTHON_=python3
if [[ -n "${PYTHON}" ]]; then
    PYTHON_=$PYTHON
fi
$PYTHON_ --version >/dev/null 2>&1 || exit_failure "Python3 is not installed or not aliased as python3, please install Python3"
$PYTHON_ -m mde_tools &>/dev/null

# If support_tool exited with exit code 5 we should install missing libraries
if [ $? = $PACKAGE_MISSING_EXIT_CODE ]; then
    echo "installing dependencies to $PYTHONUSERBASE (Nothing is installed system-wide)..."

    if ! $PYTHON_ -m pip --version &> /dev/null; then
        major_ver=$($PYTHON_ -c "import sys;print(sys.version_info[1])")
        echo "Installing pip for Python 3.$major_ver"
        if [ "$major_ver" -lt 7 ]; then
            curl https://bootstrap.pypa.io/pip/3."$major_ver"/get-pip.py -o "$PYTHONUSERBASE/get-pip.py"
        fi
        $PYTHON_ "$PYTHONUSERBASE/get-pip.py" --user
    fi

    while IFS= read -r dep; do
        $PYTHON_ -m pip install --user "$dep" || exit_failure "Failed to install $dep in mde_tools directory"
    done < "$DIR"/requirements.txt

    echo -e "\ninstalling optional dependencies to $PYTHONUSERBASE (Nothing is installed system-wide)..."
    while IFS= read -r dep; do
        $PYTHON_ -m pip install --user "$dep" 2>/dev/null || echo "[WARNING] Unable to install optional dependency $dep"
    done < "$DIR"/optional-requirements.txt
fi

(cd "$DIR" && $PYTHON_ -m mde_tools "$@")
