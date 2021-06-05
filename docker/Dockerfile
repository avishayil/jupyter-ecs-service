FROM jupyterhub/jupyterhub

MAINTAINER Project Jupyter <ipython-dev@scipy.org>

# Install oauthenticator from git
RUN python3 -m pip install oauthenticator notebook

# Create oauthenticator directory and put necessary files in it
RUN mkdir /srv/oauthenticator
WORKDIR /srv/oauthenticator
ENV OAUTHENTICATOR_DIR /srv/oauthenticator
ADD jupyterhub_config.py jupyterhub_config.py
ADD admins /srv/oauthenticator/admins
RUN chmod 700 /srv/oauthenticator

EXPOSE 8000
CMD ["jupyterhub"]