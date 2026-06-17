Build and run, precisely. 
Layout assumed: webserver.py, Dockerfile, .dockerignore, requirements.txt 
in /srv/n8n_webserver/, with squatting_scanners/ inside it (cd /srv/n8n_webserver):

	# === set up access control lists so the docker can share files with host
	SC=/srv/n8n_webserver/squatting_scanners

	# read + traverse everywhere, write nowhere
	# (covers code, keys, and reading previous enum files for --compare-previous)
	sudo setfacl -R -m u:10001:rX "$SC"

	# write only in the data directories, with default ACLs so new files inherit
	for d in run_logs hibs_scanner/output opensquat_scanner/output dnstwist_scanner/output; do
	  sudo mkdir -p "$SC/$d"
	  sudo setfacl -R  -m u:10001:rwX "$SC/$d"
	  sudo setfacl -R -d -m u:10001:rwX "$SC/$d"
	done

	# the shared out file: pre-create it and grant rw on the FILE only.
	# The app opens it with "w", which needs write only on the file.
	sudo touch "$SC/run_scanners.out"
	sudo setfacl -m u:10001:rw "$SC/run_scanners.out"
	
	# ===
	# after setting up ACLs, create and run docker

	docker build -t squat-scan-api .

	docker run -d \
	  --name squat-scan \
	  --restart unless-stopped \
	  -p 127.0.0.1:8000:8000 \
	  -p 172.30.0.13:8000:8000 \
	  -v /srv/n8n_webserver/squatting_scanners:/app/squatting_scanners \
	  squat-scan-api
	  
	for opensquat to return results run a cronjob with the keyword to check 
	on the local machine as the user who owns the directory. 
	Set ownership recursively: sudo chown -R www-data:www-data squatting_scanners,
	also set it to www-data for other files: cron.log, webserver.py.
		5 7 * * *  cd /srv/n8n_webserver && .venv/bin/python3 squatting_scanners/opensquat_scanner/opensquat_scanner.py valmiera-glass >> cron.log 2>&1

	alternatively run it inside the docker ( NOT TESTED ):
		COPY crontab /etc/cron.d/opensquat-cron
		RUN chmod 0644 /etc/cron.d/opensquat-cron && \
			crontab /etc/cron.d/opensquat-cron
		CMD cron && python webserver.py
	where 'crontab' is:
		5 7 * * * cd /app && python squatting_scanners/opensquat_scanner/opensquat_scanner.py valmiera-glass >> /app/cron.log 2>&1
	

Keep the server alive:
	sudo systemctl enable --now docker

