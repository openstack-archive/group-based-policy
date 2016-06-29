If the image is launched outside the cloud, while image booting
up it complains of not reaching meta-data agent. Since meta-data
agent will be running on network node ind OpenStack cloud.
To avoid warnings, and if image is not used in cloud infrastructre,
the cloud-init package can be removed.
