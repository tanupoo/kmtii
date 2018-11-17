#!/bin/sh

python_path=$1
pkg_dir=$2
if [ -z "$python_path" -o -z "$pkg_dir" ] ; then
    echo "Usage: $0 (python_path) (pkg_dir)"
    exit 1
fi

for name in client proxy ca repo
do
    if [ ! -d $name ] ; then
        mkdir $name
    fi
done

for name in client proxy ca repo
do
    cat <<EOD | cat - ${pkg_dir}/test/${name}.base > ${name}.sh
#!/bin/sh

python_path=${python_path}
pkg_dir=${pkg_dir}

cd ${name}/

EOD

chmod 755 ${name}.sh

done

for name in proxy ca repo
do
    openssl req -new -x509 -newkey rsa:2048 -days 7300 \
        -nodes -subj "/CN=${name}" \
        -out ${name}/${name}.pem \
        -keyout ${name}/${name}.pem
done

