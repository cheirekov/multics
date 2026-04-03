///////////////////////////////////////////////////////////////////////////////
// ANTICASC
///////////////////////////////////////////////////////////////////////////////

inline void acasc_reset(struct anticasc_data *acasc, uint32_t ticks, uint16_t sid)
{
	if (!acasc) return;
	memset(acasc, 0, sizeof(struct anticasc_data));
	acasc->window_start = ticks;
	acasc->last_sid = sid;
	acasc->sid_count = 1;
}

inline int acasc_penalty_result(struct cardserver_data *cs)
{
	if (!cs) return ANTICASC_RESULT_ALLOW;
	switch (cs->option.anticasc.penalty) {
		case ANTICASC_PENALTY_DISCONNECT:
			return ANTICASC_RESULT_DISCONNECT;
		case ANTICASC_PENALTY_DENY:
			return ANTICASC_RESULT_DENY;
		default:
			return ANTICASC_RESULT_LOG;
	}
}

inline int acasc_check(struct cardserver_data *cs, struct anticasc_data *acasc, const char *user, uint16_t caid, uint32_t provid, uint16_t sid)
{
	uint32_t ticks;
	uint32_t window_ms;
	int exceeded_ecm;
	int exceeded_sid;

	if (!cs || !acasc) return ANTICASC_RESULT_ALLOW;
	if (!cs->option.anticasc.enable) return ANTICASC_RESULT_ALLOW;
	if (!cs->option.anticasc.window) return ANTICASC_RESULT_ALLOW;

	ticks = GetTickCount();
	window_ms = cs->option.anticasc.window * 1000;

	if (!acasc->window_start || ((ticks - acasc->window_start) >= window_ms)) {
		acasc_reset(acasc, ticks, sid);
	}
	else if (!acasc->sid_count) {
		acasc->last_sid = sid;
		acasc->sid_count = 1;
	}

	acasc->ecm_count++;
	if (acasc->last_sid != sid) {
		acasc->last_sid = sid;
		acasc->sid_count++;
	}

	exceeded_ecm = cs->option.anticasc.maxecm && (acasc->ecm_count > cs->option.anticasc.maxecm);
	exceeded_sid = cs->option.anticasc.maxsid && (acasc->sid_count > cs->option.anticasc.maxsid);
	if (!exceeded_ecm && !exceeded_sid) return ANTICASC_RESULT_ALLOW;

	acasc->violations++;
	mlogf(LOGWARNING,0,
		" [ANTICASC] client '%s' ch %04x:%06x:%04x exceeded limits (ecm=%u/%u sid=%u/%u)\n",
		user ? user : "?", caid, provid, sid,
		(unsigned int)acasc->ecm_count, (unsigned int)cs->option.anticasc.maxecm,
		(unsigned int)acasc->sid_count, (unsigned int)cs->option.anticasc.maxsid);

	return acasc_penalty_result(cs);
}