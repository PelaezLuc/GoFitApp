import { useContext, useState } from "react";
import { UserAuthContext } from "../context/UserAuthContext";
import { editWorkoutService } from "../services/services";
import "./css/editExerciseModal.css";

export const EditExerciseModal = ({
  workout,
  stateEditModal,
  setStateEditModal,
  editWorkout,
}) => {
  const { userAuth } = useContext(UserAuthContext);
  const token = userAuth.token;
  const idWorkout = workout.id;

  const [name, setName] = useState("");
  const [type, setType] = useState("");
  const [description, setDescription] = useState("");
  const [muscle_group, setMuscleGroup] = useState("");
  const [video, setVideo] = useState("");
  const [error, setError] = useState("");

  const handleForm = async (e) => {
    e.preventDefault();
    setError("");

    try {
      const editedWorkout = await editWorkoutService({
        idWorkout,
        name,
        type,
        description,
        muscle_group,
        token,
      });

      editWorkout({ idWorkout, editedWorkout });

      setStateEditModal(false);
    } catch (error) {
      setError(error.message);
    }
  };

  return (
    <>
      {stateEditModal && 
          <div className="overlay-edit-modal" onClick={(e)=>{
            if ( 
                        !e.target.closest(".modal-edit-container")
                      ) {
                        setStateEditModal(false);
                      }
        }}>
          <div className="modal-edit-container">
              <div className="modal-edit-header">
                  <h1 className='logo-app'>GoFit<span className="font-family-app">APP</span></h1>
              </div>
              <br/>
              <form onSubmit={handleForm} className="modal-edit-form">
                  <div className="modal-edit-group">
                      <label className="modal-edit-label" htmlFor="name">Nombre: </label>
                      <input 
                          className="modal-edit-controls" 
                          type="text" 
                          name="name" 
                          id="name" 
                          onChange={(e) => setName(e.target.value)}
                      />
                  </div>
                  <div className="modal-edit-group">
                      <label className="modal-edit-label" htmlFor="type">Tipo: </label>
                      <input 
                          className="modal-edit-controls" 
                          type="text" 
                          name="type" 
                          id="type" 
                          placeholder="Cardio/Hipertrofia"
                          onChange={(e) => setType(e.target.value)}
                      />
                  </div>
                  <div className="modal-edit-group textarea">
                      <label className="modal-label" htmlFor="description">Descripción: </label>
                      <textarea  className="modal-controls description" 
                          type="text" 
                          name="description" 
                          id="description" 
                          maxlength="200"
                          onChange={(e) => setDescription(e.target.value)}>
                      </textarea>
                  </div>
                  <div className="modal-edit-group">
                      <label className="modal-label" htmlFor="muscle-group">Músculo/s: </label>
                      <input 
                          className="modal-edit-controls" 
                          type="text" 
                          name="muscle-group" 
                          id="muscle-group" 
                          onChange={(e) => setMuscleGroup(e.target.value)}
                      />
                  </div>
                  {/* <div className="modal-edit-group">
                      <label className="modal-label" htmlFor="video">Vídeo: </label>
                      <input 
                          className="modal-edit-controls video" 
                          type="file" 
                          name="video" 
                          id="video" 
                          onChange={(e) => setVideo(e.target.value)}
                      />
                  </div> */}
                  <input 
                      className="modal-edit-submit-btn" 
                      type="submit" 
                      value="Editar ejercicio"
                  />
                  {error ? <p>{error}</p> : null}
              </form>
          </div>
      </div>
    }
    </>
  )
}