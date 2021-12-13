# Development

build-env:
	@echo -e "\
	QUART_ENV=development\n\
	QUART_APP=auth_server:app\n\
	JWT_ACCESS_SECRET_KEY=change_me\n\
	JWT_REFRESH_SECRET_KEY=change_me\
	" > .env
	
clean:
	@echo 'Cleaning up...'
	rm .env
