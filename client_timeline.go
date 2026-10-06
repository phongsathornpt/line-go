package line

import "github.com/phongsathornpt/line-go/base"

// Timeline returns LINE's Timeline/VOOM JSON service, initialized with the
// account MID when this client has loaded a profile.
func (c *Client) Timeline() *base.TimelineService {
	if c == nil || c.base == nil {
		return nil
	}
	if c.profile != nil {
		c.base.SetProfileMID(c.profile.MID)
	}
	return c.base.Timeline()
}
