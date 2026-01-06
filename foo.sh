zaa-mqtt-monitor (){

		local TOPIC_FG=${COLORS[GREEN]};
		local PAYLOAD_FG=${COLORS[CYAN]};
		local RESET=${COLORS[RESET]};
		while :; do
			mosquitto_sub -q 2 -t '#' -h databases -F "@Y-@m-@d @H:@m:@S ${TOPIC_FG}%t ${PAYLOAD_FG}%p${RESET}" | \
			while read LINE; do
				echo -e "${LINE}"
			done
			echo hi
		done


}
