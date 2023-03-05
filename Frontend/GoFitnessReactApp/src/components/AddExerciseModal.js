import { useContext, useState } from "react";
import { UserAuthContext } from "../context/UserAuthContext";
import { addWorkoutService } from "../services/services";
import './css/addExerciseModal.css';

export const AddExerciseModal = ({
    stateAddModal,
    setStateAddModal,
    addWorkout,
  }) => {
    const { userAuth } = useContext(UserAuthContext);
    const token = userAuth.token;
  
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
        const workout = await addWorkoutService({
          name,
          type,
          description,
          muscle_group,
          token,
        });
  
        addWorkout(workout);
  
        setStateAddModal(false);
      } catch (error) {
        setError(error.message);
      }
    };

    return (
        <>
        {stateAddModal && 
            <div className="overlay-modal" onClick={(e)=>{
                if (
                            !e.target.closest(".modal-container")
                          ) {
                            setStateAddModal(false);
                          }
            }}>
                <div className="modal-container">
                    <div className="modal-header">
                        <h1 className='logo-app'>GoFit<span className="font-family-app">APP</span></h1>
                    </div>
                    <br/>
                    <form onSubmit={handleForm} className="modal-form">
                        <div className="modal-group">
                            <label className="modal-label" htmlFor="name">Nombre: </label>
                            <input 
                                className="modal-controls" 
                                type="text" 
                                name="name" 
                                id="name" 
                                required 
                                onChange={(e) => setName(e.target.value)}
                            />
                        </div>
                        <div className="modal-group">
                            <label className="modal-label" htmlFor="type">Tipo: </label>
                            <input 
                                className="modal-controls" 
                                type="text" 
                                name="type" 
                                id="type" 
                                placeholder="Cardio/Hipertrofia"
                                required
                                onChange={(e) => setType(e.target.value)}
                            />
                        </div>
                        <div className="modal-group textarea">
                            <label className="modal-label" htmlFor="description">Descripción: </label>
                            <textarea  className="modal-controls description" 
                                type="text" 
                                name="description" 
                                id="description" 
                                maxlength="200"
                                required
                                onChange={(e) => setDescription(e.target.value)}>
                            </textarea>
                        </div>
                        <div className="modal-group">
                            <label className="modal-label" htmlFor="muscle-group">Músculo/s: </label>
                            <input 
                                className="modal-controls" 
                                type="text" 
                                name="muscle-group" 
                                id="muscle-group" 
                                required
                                onChange={(e) => setMuscleGroup(e.target.value)}
                            />
                        </div>
                        {/*<div className="modal-group">
                            <label className="modal-label" htmlFor="video">Vídeo: </label>
                            <input 
                                className="modal-controls video" 
                                type="file" 
                                name="video" 
                                id="video" 
                                onChange={(e) => setVideo(e.target.value)}
                            />
                        </div> */}
                        <input 
                            className="modal-submit-btn" 
                            type="submit" 
                            value="Añadir Ejercicio"
                        />
                        {error ? <p>{error}</p> : null}
                    </form>
                </div>
            </div>
        }
        </>
    )
}
