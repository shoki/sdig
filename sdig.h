/* sdig.h - switch digger structures */

/* switch information */

typedef struct {
	unsigned int	addr;
	unsigned int	mask;
	char	*ip;
	char	*desc;
	char	*pw;
	char	*vendor;
	unsigned int	vlanid;
	void	*firstlink;
	void	*next;
}	stype;

/* router information */

typedef struct {
	unsigned int	addr;
	unsigned int	mask;
	char	*ip;
	char	*desc;
	char	*pw;
	void	*next;
}	rtype;

/* switch-switch link information */

typedef struct {
	char    *ip;
	long	port;
	char    *desc;
	void    *next;
}       litype;

/* switch port descriptions */

typedef struct {
	char    *ip;
	long	port;
	char    *desc;
	void    *next;
}       pdtype;
