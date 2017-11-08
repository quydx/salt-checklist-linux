def test():
    """
    Test module function
    """
    cmd = 'echo hello'
    out = __salt__['cmd.run'](cmd).splitlines()
    ret = out[0]
    return ret

def detect_os():
    """
    Test load __detect_os() from main module
    """
    cmd  = '{0} -h'.format( __salt__['nginx.__detect_os']()
    out = __salt__['cmd.run'](cmd).splitlines()
    ret = out[0]
    return ret

