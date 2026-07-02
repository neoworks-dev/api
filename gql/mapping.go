package gql

type surrealContact struct {
	ID        string  `json:"id"`
	FirstName string  `json:"first_name"`
	LastName  string  `json:"last_name"`
	Email     *string `json:"email"`
	Phone     *string `json:"phone"`
	CreatedAt string  `json:"created_at"`
}
 
// func mapContacts(raw any) ([]*model.Contact, error) {
// 	b, err := json.Marshal(raw)
// 	if err != nil {
// 		return nil, fmt.Errorf("marshal: %w", err)
// 	}
 
// 	// SurrealDB returns [[result]] for queries
// 	var outer [][]surrealContact
// 	if err := json.Unmarshal(b, &outer); err != nil {
// 		return nil, fmt.Errorf("unmarshal: %w", err)
// 	}
// 	if len(outer) == 0 {
// 		return nil, nil
// 	}
 
// 	out := make([]*model.Contact, len(outer[0]))
// 	for i, c := range outer[0] {
// 		// Strip the "contacts:" prefix SurrealDB adds to IDs
// 		id := c.ID
// 		if len(id) > 9 {
// 			id = id[9:]
// 		}
// 		out[i] = &model.Contact{
// 			ID:        id,
// 			FirstName: c.FirstName,
// 			LastName:  c.LastName,
// 			Email:     c.Email,
// 			Phone:     c.Phone,
// 			CreatedAt: c.CreatedAt,
// 		}
// 	}
// 	return out, nil
// }