#!/bin/bash
function ejecutar {
  printf "\nInstalando maruja...\n\n"
  read -p "Tamaño del firewall (10 por defecto ) -> " tam
  if [[ $tam -le 0 ]]; then
    echo "¿Qué haces pasando un tamaño negativo?"
    exit 0
  fi

  if [[ "$tam" == "" ]]; then
    sudo insmod maruja.ko
  else
    sudo insmod maruja.ko fw_ip_count_max=$tam
  fi

  sudo dmesg | tail

  read -p "Major de maruja -> " major

  printf "\nCreando /dev/maruja y poniendo los permisos correctos...\n"
  sudo mknod /dev/maruja c $major 0
  sudo chmod 777 /dev/maruja

  while true;
  do
    read -p "Dame una ip a bloquear (exit para irte y dmesg para ver el log) -> " block
    if [[ "$block" == "exit" ]]; then
      printf "Limpiando...\n"
      sudo rm /dev/maruja
      echo "/dev/maruja eliminado"
      sudo rmmod maruja
      echo "maruja eliminado completamente"
      echo "Cerrando..."
      exit 0
    elif [[ "$block" == "dmesg" ]]; then
      sudo dmesg | tail
    elif [[ "$block" == "read" ]]; then
          cat /dev/maruja
          sudo dmesg | tail
    else
      echo "$block" > /dev/maruja
      sudo dmesg | tail
    fi
  done
}

function limpiar {
  sudo rm /dev/maruja
  sudo rmmod maruja
  sudo dmesg | tail
}

# --------------------------------------------------------------------------------------------


echo "No me seas y lanza el programa desde el directorio raíz (./driver)"
printf "\n\n"
read -p "¿Compilar o ejecutar? (C/E) -> " mode


if [[ "$mode" == "E" || "$mode" == "e" ]]; then
  if ! ls | grep -q bin; then
    read -p "No hay bin en el directorio raíz, ¿crear, compilar y ejecutar? (S/N) -> " siono
    if [[ "$siono" == "S" || "$siono" == "s" ]]; then
      mkdir bin
      if ! ls | grep -q src; then
        printf "No hay src en el directorio raíz, no hay código, cerrando...\n"
        exit 0
      fi
      cd src
      if ! ls | grep -q Makefile; then
        printf "No hay Makefile en el directorio src, cerrando...\n"
        exit 0
      fi
      if ! ls | grep -q maruja.c; then
        printf "No hay maruja.c en el directorio src, no hay código, cerrando...\n"
        exit 0
      fi
      make
      cp maruja.ko ../bin/maruja.ko
      make clean
      cd ../bin
      ejecutar
      limpiar
      cd ..
      exit 0
    else
      echo "Cerrando..."
      exit 0
    fi
  else
    cd bin
    if ! ls | grep -q maruja.ko; then
      read -p "No hay driver, ¿quieres compilar y ejecutar? (S/N) -> \n" lqsea
      if [[ "$lqsea" == "S" || "$lqsea" == "s" ]]; then
        cd ..
        if ! ls | grep -q src; then
          printf "No hay src en el directorio raíz, no hay código, cerrando...\n"
          exit 0
        fi
        printf "Compilando\n\n"
        cd src
        if ! ls | grep -q Makefile; then
          printf "No hay Makefile en el directorio src, cerrando...\n"
          exit 0
        fi
        if ! ls | grep -q maruja.c; then
          printf "No hay maruja.c en el directorio src, no hay código, cerrando...\n"
          exit 0
        fi
        make
        printf "\nListo, copiando maruja.ko a bin y limpiando...\n\n"
        cp maruja.ko ../bin/maruja.ko
        make clean
        cd ../bin
        printf "\nEjecutando..."
        ejecutar
        printf "\nListo, cerrando..."
        cd ..
        limpiar
        exit 0
      else
        echo "Cerrando..."
        exit 0
      fi
    else
      printf "\nEjecutando..."
      ejecutar
      printf "\nListo, cerrando..."
      limpiar
      cd ..
      exit 0
    fi
  fi
elif [[ "$mode" == "C" || "$mode" == "c" ]]; then
  if ! ls | grep -q src; then
    printf "No hay src en el directorio raíz, no hay código, cerrando...\n"
    exit 0
  fi
  printf "Compilando\n\n\n"
  cd src
  if ! ls | grep -q Makefile; then
    printf "No hay Makefile en el directorio src, cerrando...\n"
    exit 0
  fi
  if ! ls | grep -q maruja.c; then
    printf "No hay maruja.c en el directorio src, no hay código, cerrando...\n"
    exit 0
  fi
  make
  printf "\n\nListo, copiando maruja.ko a bin y limpiando...\n\n\n"
  if ! ls .. | grep -q bin; then
      mkdir ../bin
  fi
  cp maruja.ko ../bin/maruja.ko
  make clean
  cd ..
  printf "\n\n"
  read -p "¿Ejecutar? (S/N) -> " eing
  if [[ "$eing" == "S" || "$eing" == "s" ]]; then
    cd bin
    printf "\nEjecutando...\n"
    ejecutar
    printf "\nListo, cerrando...\n"
    limpiar
    cd ..
    exit 0
  else
    echo "Cerrando..."
    exit 0
  fi
else
  echo "Me has dado un modo que no te pedía"
  exit 0
fi