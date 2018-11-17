#!/bin/sh

python_path=$1
bin_path=$2
if [ -z "$python_path" -o -z "$bin_path" ] ; then
    echo "Usage: $0 (python_path) (bin_path)"
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
    cat <<EOD | cat - ../${name}.base > ${name}.sh
#!/bin/sh

python_path=${python_path}
bin_path=${bin_path}

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

